-- Your SQL goes here
CREATE TABLE registered_heads (id INTEGER PRIMARY KEY NOT NULL, head TEXT NOT NULL);

CREATE TABLE emails (id INTEGER PRIMARY KEY NOT NULL, registered_head_id INTEGER NOT NULL, domain TEXT NOT NULL, sender TEXT NOT NULL, message TEXT NOT NULL, FOREIGN KEY (registered_head_id) REFERENCES registered_heads(id));
