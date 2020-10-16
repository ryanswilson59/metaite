pub mod models;
pub mod schema;

use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::BytesMut;

use futures_util::future::{select, Either};
use futures_util::future::{FutureExt, TryFutureExt};
use futures_util::pin_mut;
use futures_util::stream::Stream;
use futures_util::stream::TryStreamExt;

use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::runtime::Runtime;
use tokio::sync::oneshot::Receiver;

use failure::{format_err, Error};
use tokio_rustls::rustls::{
    internal::pemfile::{certs, rsa_private_keys},
    NoClientAuth, ServerConfig, ServerSession, Session,
};
use tokio_rustls::TlsAcceptor;

use rustyknife::rfc5321::{ForwardPath, Param, Path, ReversePath};
use rustyknife::types::{Domain, DomainPart};
use smtpbis::{
    smtp_server, Config, EhloKeywords, Handler, LineError, LoopExit, Reply, ServerError,
    ShutdownSignal,
};

#[macro_use]
extern crate diesel;
use diesel::prelude::*;
use diesel::sqlite;
use diesel::sqlite::SqliteConnection;
use mxdns::MxDns;

use std::env;

const CERT: &[u8] = include_bytes!("../testcert.pem");
const KEY: &[u8] = include_bytes!("../testcert.key");

const DEFAULT_ADDRESS: &str = "127.0.0.1:8080";

const OPT_ADDRESS: &str = "address";
const OPT_HELP: &str = "help";
const OPT_BLOCKLIST: &str = "cowlist";

struct IteHandler {
    mxdns: Arc<MxDns>,
    tls_config: Arc<ServerConfig>,
    addr: SocketAddr,
    helo: Option<DomainPart>,
    mail: Option<ReversePath>,
    rcpt: Vec<ForwardPath>,
    body: Vec<u8>,
    conn: Arc<Mutex<SqliteConnection>>,
}

#[async_trait]
impl Handler for IteHandler {
    type TlsConfig = Arc<ServerConfig>;
    type TlsSession = ServerSession;

    async fn tls_request(&mut self) -> Option<Self::TlsConfig> {
        Some(self.tls_config.clone())
    }

    async fn tls_started(&mut self, session: &Self::TlsSession) {
        println!(
            "TLS started: {:?}/{:?}",
            session.get_protocol_version(),
            session.get_negotiated_ciphersuite()
        );
        self.reset_tx();
    }

    async fn ehlo(
        &mut self,
        domain: DomainPart,
        mut initial_keywords: EhloKeywords,
    ) -> Result<(String, EhloKeywords), Reply> {
        initial_keywords.insert("DSN".into(), None);
        initial_keywords.insert("8BITMIME".into(), None);
        initial_keywords.insert("SIZE".into(), Some("73400320".into()));
        //TODO stat
        let rdns = self.mxdns.fcrdns(self.addr.ip());
        match rdns {
            Ok(ref res) if !res.is_confirmed() => {
                //stat fail.fcrdns
                Result::Err(Reply::new(550, None, ""))
            }
            _ => {
                if self.mxdns.is_blocked(self.addr.ip()).unwrap_or(false) {
                    //stat blocked
                    Result::Err(Reply::new(550, None, ""))
                } else {
                    let greet = format!("hello {} from {}", domain, self.addr);
                    self.helo = Some(domain);
                    self.reset_tx();

                    Ok((greet, initial_keywords))
                }
            }
        }
    }

    //no helo, only ehlo
    async fn helo(&mut self, domain: Domain) -> Option<Reply> {
        //stat ehlo vs helo and domain
        let rdns = self.mxdns.fcrdns(self.addr.ip());
        match rdns {
            Ok(ref res) if !res.is_confirmed() => {
                //stat fail.fcrdns
                Option::Some(Reply::new(550, None, ""))
            }
            _ => {
                if self.mxdns.is_blocked(self.addr.ip()).unwrap_or(false) {
                    //stat blocked
                    Option::Some(Reply::new(550, None, ""))
                } else {
                    let greet = format!("hello {} from {}", domain, self.addr);
                    self.helo = Some(DomainPart::Domain(domain));
                    self.reset_tx();

                    Some(Reply::new(250, None, greet))
                }
            }
        }
    }

    async fn mail(&mut self, path: ReversePath, _params: Vec<Param>) -> Option<Reply> {
        println!("Handler MAIL: {:?}", path);

        self.mail = Some(path);
        None
    }

    async fn rcpt(&mut self, path: ForwardPath, _params: Vec<Param>) -> Option<Reply> {
        println!("Handler RCPT: {:?}", path);
        self.rcpt.push(path);
        None
    }

    async fn data_start(&mut self) -> Option<Reply> {
        println!("Handler DATA start");
        None
    }

    async fn data<S>(&mut self, stream: &mut S) -> Result<Option<Reply>, ServerError>
    where
        S: Stream<Item = Result<BytesMut, LineError>> + Unpin + Send,
    {
        println!("Handler DATA read");
        let mut nb_lines: usize = 0;
        self.body.clear();

        while let Some(line) = stream.try_next().await? {
            self.body.extend(line);
            nb_lines += 1;
        }

        println!("got {} body lines", nb_lines);
        let reply_txt = format!("Received {} bytes in {} lines.", self.body.len(), nb_lines);
        self.reset_tx();

        Ok(Some(Reply::new(250, None, reply_txt)))
    }

    async fn bdat<S>(
        &mut self,
        stream: &mut S,
        _size: u64,
        last: bool,
    ) -> Result<Option<Reply>, ServerError>
    where
        S: Stream<Item = Result<BytesMut, LineError>> + Unpin + Send,
    {
        while let Some(chunk) = stream.try_next().await? {
            self.body.extend(chunk)
        }
        if last {
            self.reset_tx();
        }

        Ok(None)
    }

    async fn rset(&mut self) {
        self.reset_tx();
    }
}

impl IteHandler {
    fn reset_tx(&mut self) {
        println!("Reset!");
        self.mail = None;
        self.rcpt.clear();
        self.body.clear();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    //     let addr = "127.0.0.1:25".parse::<SocketAddr>()?;

    let mut rt = Runtime::new()?;

    rt.block_on(async {
        let (listen_shutdown_tx, listen_shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(listen_loop(listen_shutdown_rx));

        tokio::signal::ctrl_c().await.unwrap();
        listen_shutdown_tx.send(()).unwrap();
        println!("Waiting for tasks to finish...");
        // FIXME: actually wait on tasks here.
    });

    Ok(())
}

async fn listen_loop(mut shutdown: Receiver<()>) {
    let args: Vec<String> = env::args().collect();
    let mut opts = getopts::Options::new();

    opts.optopt("a", OPT_ADDRESS, "the address to listen on", "ADDRESS");
    opts.optflag("h", OPT_HELP, "print this help menu");
    opts.optmulti("", OPT_BLOCKLIST, "use blocklist", "BLOCKLIST");

    let matches = opts
        .parse(&args[1..])
        .map_err(|err| format_err!("Error parsing command line: {}", err))
        .unwrap();

    let blocklists = matches.opt_strs(OPT_BLOCKLIST);
    let mxdns = Arc::new(
        MxDns::new(blocklists)
            .map_err(|e| format_err!("{}", e))
            .unwrap(),
    );

    let addr = matches
        .opt_str(OPT_ADDRESS)
        .unwrap_or_else(|| DEFAULT_ADDRESS.to_owned());
    let mut listener = TcpListener::bind(addr).await.unwrap();

    //TODO change allowed auth
    let mut tls_config = ServerConfig::new(NoClientAuth::new());
    let certs = certs(&mut Cursor::new(CERT)).unwrap();
    let key = rsa_private_keys(&mut Cursor::new(KEY)).unwrap().remove(0);
    tls_config.set_single_cert(certs, key).unwrap();
    let tls_config = Arc::new(tls_config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_rx = shutdown_rx.map_err(|_| ()).shared();

    let conn = SqliteConnection::establish("test.sqlite3").unwrap();
    let conn = Arc::new(Mutex::new(conn));

    loop {
        let accept = listener.accept();
        pin_mut!(accept);

        match select(accept, &mut shutdown).await {
            Either::Left((listen_res, _)) => {
                let (socket, addr) = listen_res.unwrap();
                let mut shutdown_rx = shutdown_rx.clone();
                let tls_config = tls_config.clone();
                let mxdns = mxdns.clone();
                let conn = conn.clone();

                tokio::spawn(async move {
                    let smtp_res =
                        serve_smtp(socket, addr, tls_config, mxdns, conn, &mut shutdown_rx).await;
                    println!("SMTP task done: {:?}", smtp_res);
                })
            }
            Either::Right(..) => {
                println!("socket listening loop stopping");
                shutdown_tx.send(()).unwrap();
                break;
            }
        };
    }
}

async fn serve_smtp(
    mut socket: TcpStream,
    addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    mxdns: Arc<MxDns>,
    conn: Arc<Mutex<SqliteConnection>>,
    shutdown: &mut ShutdownSignal,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut handler = IteHandler {
        mxdns,
        addr,
        tls_config,
        conn,
        helo: None,
        mail: None,
        rcpt: Vec::new(),
        body: Vec::new(),
    };

    let mut config = Config::default();
    match smtp_server(&mut socket, &mut handler, &config, shutdown, true).await {
        Ok(LoopExit::Done) => println!("Server done"),
        Ok(LoopExit::STARTTLS(tls_config)) => {
            let acceptor = TlsAcceptor::from(tls_config);
            let mut tls_socket = acceptor.accept(socket).await?;
            config.enable_starttls = false;
            handler.tls_started(tls_socket.get_ref().1).await;
            match smtp_server(&mut tls_socket, &mut handler, &config, shutdown, false).await {
                Ok(_) => println!("TLS Server done"),
                Err(e) => println!("TLS Top level error: {:?}", e),
            }
            tls_socket.shutdown().await?;
        }
        Err(e) => println!("Top level error: {:?}", e),
    }

    Ok(())
}
