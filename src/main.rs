pub mod models;
pub mod schema;

use std::boxed::Box;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::BytesMut;
use chrono::prelude::*;

use futures_util::future::{select, Either};
use futures_util::future::{FutureExt, TryFutureExt};
use futures_util::pin_mut;
use futures_util::stream::Stream;
use futures_util::stream::TryStreamExt;

use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::runtime::Runtime;
use tokio::sync::oneshot::Receiver;
use tokio::{pin, select};

use tokio_rustls::rustls::{
    internal::pemfile::{certs, rsa_private_keys},
    NoClientAuth, ServerConfig, ServerSession, Session,
};
use tokio_rustls::TlsAcceptor;

use rustyknife::rfc5321::{ForwardPath, Param, Path, ReversePath};
use rustyknife::types::{Domain, DomainPart, LocalPart};
use smtpbis::{
    smtp_server, Config, EhloKeywords, Handler, LineError, LoopExit, Reply, ServerError,
    ShutdownSignal,
};

#[macro_use]
extern crate diesel;
use self::models::{Email, NewEmail, NewHead, RegisteredHead};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use mxdns::MxDns;

use failure::format_err;

const CERT: &[u8] = include_bytes!("../testcert.pem");
const KEY: &[u8] = include_bytes!("../testcert.key");

const DEFAULT_ADDRESS: &str = "127.0.0.1:8080";
const DEFAULT_LOG_PATH: &str = "log.log";

const OPT_LOG_PATH: &str = "log path";
const OPT_ADDRESS: &str = "address";
const OPT_HELP: &str = "help";
const OPT_BLOCKLIST: &str = "cowlist";

struct IteHandler {
    tls_config: Arc<ServerConfig>,
    addr: SocketAddr,
    helo: Option<DomainPart>,
    mail: Option<ReversePath>,
    rcpt: Vec<ForwardPath>,
    rcpt_id: Vec<Option<i32>>,
    body: Vec<u8>,
    mxdns: Arc<MxDns>,
    conn: Arc<Mutex<SqliteConnection>>,
    log: Arc<Mutex<File>>,
}

//TODO more sophisticated anti spoofing?

#[async_trait]
impl Handler for IteHandler {
    type TlsConfig = Arc<ServerConfig>;
    type TlsSession = ServerSession;

    async fn tls_request(&mut self) -> Option<Self::TlsConfig> {
        self.log("tls_request", false);
        Some(self.tls_config.clone())
    }

    async fn tls_started(&mut self, session: &Self::TlsSession) {
        self.log(
            &format!(
                "TLS started: {:?}/{:?}",
                session.get_protocol_version(),
                session.get_negotiated_ciphersuite()
            ),
            false,
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
        self.log("ehlo", false);
        let rdns = self.mxdns.fcrdns(self.addr.ip());
        match rdns {
            Ok(ref res) if !res.is_confirmed() => {
                self.log("failed rdns", false);
                //stat fail.fcrdns
                Result::Err(Reply::new(550, None, ""))
            }
            _ => {
                if self.mxdns.is_blocked(self.addr.ip()).unwrap_or(false) {
                    //stat blocked
                    self.log(&format!("blocked {}", self.addr.ip()), false);
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

    async fn helo(&mut self, domain: Domain) -> Option<Reply> {
        self.log(&format!("helo try"), false);
        if self.addr.ip() == Ipv4Addr::new(127, 0, 0, 1) {
            let greet = format!("hello {} from {}", domain, self.addr);
            self.helo = Some(DomainPart::Domain(domain));
            self.reset_tx();

            return Some(Reply::new(250, None, greet));
        }

        let rdns = self.mxdns.fcrdns(self.addr.ip());
        match rdns {
            Ok(ref res) if !res.is_confirmed() => {
                //stat fail.fcrdns
                Some(Reply::new(550, None, ""))
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
        self.log(&format!("Handler MAIL: {:?}", &path), false);
        if let Some(helo_domain) = &self.helo {
            match &path {
                ReversePath::Path(a_path) => {
                    if a_path.0.domain_part() == helo_domain {
                        self.mail = Some(path);
                        return None;
                    } else {
                        self.log(
                            &format!(
                                "{} and {} do not match",
                                a_path.0.domain_part(),
                                helo_domain
                            ),
                            true,
                        );
                        self.mail = Some(path);
                        return None;
                    }
                }
                _ => {
                    return Some(Reply::new(550, None, ""));
                }
            }
        }

        return Some(Reply::new(550, None, ""));
    }

    async fn rcpt(&mut self, path: ForwardPath, _params: Vec<Param>) -> Option<Reply> {
        self.log(&format!("Handler RCPT: {:?}", path), false);

        if let ForwardPath::Path(Path(mbox, _)) = &path {
            let v;
            let head = match mbox.local_part() {
                LocalPart::DotAtom(s) => s.chars().as_str(),
                LocalPart::Quoted(s) => {
                    v = s.quoted();
                    v.as_str()
                }
            };
            let i_conn_r = self.conn.lock().unwrap();
            let i_conn = i_conn_r.deref();
            let res = schema::registered_heads::table
                .filter(schema::registered_heads::head.eq_all(head))
                .load::<models::RegisteredHead>(i_conn)
                .expect("Error Loading Rcpt");
            if res.len() > 0 {
                self.rcpt.push(path);
                self.rcpt_id.push(Some(res[0].id));
            } else {
                self.log(&format!("Invalid Head Rcpt"), true);
                return Some(Reply::new(550, None, ""));
            }
        };

        None
    }

    async fn data_start(&mut self) -> Option<Reply> {
        self.log(&format!("Handler DATA start"), false);
        None
    }

    async fn data<S>(&mut self, stream: &mut S) -> Result<Option<Reply>, ServerError>
    where
        S: Stream<Item = Result<BytesMut, LineError>> + Unpin + Send,
    {
        self.log(&format!("Handler DATA read"), false);
        let mut nb_lines: usize = 0;
        self.body.clear();

        while let Some(line) = stream.try_next().await? {
            self.body.extend(line);
            nb_lines += 1;
        }

        for m_id in &self.rcpt_id {
            match m_id {
                Some(id) => {
                    if let Some(ReversePath::Path(from)) = &self.mail {
                        let v;
                        let sender = match from.0.local_part() {
                            LocalPart::DotAtom(s) => s.chars().as_str(),
                            LocalPart::Quoted(s) => {
                                v = s.quoted();
                                v.as_str()
                            }
                        };

                        let new_mail = match from.0.domain_part() {
                            DomainPart::Domain(v) => {
                                let domain = v.chars().as_str();
                                let message =
                                    std::str::from_utf8(&self.body).expect("UTF8 error");
                                NewEmail {
                                    registered_head_id: *id,
                                    sender,
                                    domain,
                                    message,
                                }
                            }
                            DomainPart::Address(_) => {
                                //TODO doubt ill ever need this.
                                //really need to add logging
                                return Result::Ok(Some(Reply::new(550, None, "")));
                            }
                        };

                        let i_conn_r = self.conn.lock().unwrap();
                        let i_conn = i_conn_r.deref();
                        diesel::insert_into(schema::emails::table)
                            .values(&new_mail)
                            .execute(i_conn)
                            .expect("Failed to write email");
                    }
                }
                None => {}
            }
        }

        self.log(&format!("got {} body lines", nb_lines), false);
        let reply_txt =
            format!("Received {} bytes in {} lines.", self.body.len(), nb_lines);
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
        self.log(&format!("Reset!"), false);
        self.mail = None;
        self.rcpt.clear();
        self.body.clear();
    }

    fn log(&self, msg: &str, err: bool) {
        let i_log_r = self.log.lock().unwrap();
        let mut i_log = i_log_r.deref();
        let time = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let level = match err {
            true => "ERROR",
            false => " INFO",
        };
        let write = format!("{} [{}] usage: {}", time, level, msg);
        if let Err(e) = writeln!(i_log, "{}", &write) {
            panic!("log fail, {}", e);
        }
        println!("{}", &write);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    opts.optopt("l", OPT_LOG_PATH, "the path to the logfile", "LOG_PATH");
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

    let log_path = matches
        .opt_str(OPT_LOG_PATH)
        .unwrap_or_else(|| DEFAULT_LOG_PATH.to_owned());
    let log = match OpenOptions::new().write(true).append(true).open(&log_path) {
        Err(e) => panic!("couldn't open {}: {}", log_path, e),
        Ok(f) => Arc::new(Mutex::new(f)),
    };

    let mut t_shut = shutdown_rx.clone();
    let t_conn = conn.clone();
    tokio::spawn(async move { control_loop(t_conn, &mut t_shut).await });

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
                let log = log.clone();

                tokio::spawn(async move {
                    let smtp_res = serve_smtp(
                        socket,
                        addr,
                        tls_config,
                        mxdns,
                        conn,
                        log,
                        &mut shutdown_rx,
                    )
                    .await;
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

async fn control_loop(
    conn: Arc<Mutex<SqliteConnection>>,
    shutdown: &mut ShutdownSignal,
) -> () {
    // let mut input = std::io::stdin();
    // let mut input = tokio::io::stdin();
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    pin!(shutdown);

    loop {
        #[rustfmt::skip]
        select! {
            _ = &mut shutdown => {
		//quit
		break;
            }
            res = lines.next_line() => {
		match res {
		    Ok(m_buff)=>{
			let buff=match m_buff{
			    Some(v) => v,
			    None => String::new()
			};
			println!("{}", buff);
			let mut first = true;
			let mut mode = "";
			let args = buff.split(" ");
			for a in args {
			    if first {
				mode = a;
				first = false;
			    } else {
				match mode {
				    "add-head" => add_head(conn.clone(), a),
				    _ => println!("invalid command"),
				}
			    }
			}
		    }
		    Err(e) => println!("{}",e)
		}
            }
        }
    }
}

async fn serve_smtp(
    mut socket: TcpStream,
    addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    mxdns: Arc<MxDns>,
    conn: Arc<Mutex<SqliteConnection>>,
    log: Arc<Mutex<File>>,
    shutdown: &mut ShutdownSignal,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut handler = IteHandler {
        addr,
        tls_config,
        mxdns,
        conn,
        log,
        helo: None,
        mail: None,
        rcpt_id: Vec::new(),
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
            match smtp_server(&mut tls_socket, &mut handler, &config, shutdown, false)
                .await
            {
                Ok(_) => println!("TLS Server done"),
                Err(e) => println!("TLS Top level error: {:?}", e),
            }
            tls_socket.shutdown().await?;
        }
        Err(e) => println!("Top level error: {:?}", e),
    }

    Ok(())
}

fn add_head(conn: Arc<Mutex<SqliteConnection>>, head: &str) {
    let i_conn_r = conn.lock().unwrap();
    let i_conn = i_conn_r.deref();
    let new_head = NewHead { head };
    diesel::insert_into(schema::registered_heads::table)
        .values(&new_head)
        .execute(i_conn)
        .expect("Error Registering Head");
}
