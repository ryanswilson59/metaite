use crate::schema;
use schema::{emails, registered_heads};

#[derive(Identifiable, Queryable)]
#[table_name = "registered_heads"]
pub struct RegisteredHead {
    pub id: i32,
    pub head: String,
}

#[derive(Insertable)]
#[table_name = "registered_heads"]
pub struct NewHead<'a> {
    pub head: &'a str,
}

#[derive(Identifiable, Queryable, Associations)]
#[belongs_to(RegisteredHead)]
#[table_name = "emails"]
pub struct Email {
    id: i32,
    registered_head_id: i32,
    domain: String,
    sender: String,
    message: String,
}

#[derive(Insertable, Associations)]
#[belongs_to(RegisteredHead)]
#[table_name = "emails"]
pub struct NewEmail<'a> {
    pub registered_head_id: i32,
    pub domain: &'a str,
    pub sender: &'a str,
    pub message: &'a str,
}
