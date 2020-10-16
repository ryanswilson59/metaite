table! {
    emails (id) {
        id -> Integer,
        registered_head_id -> Integer,
        domain -> Text,
        sender -> Text,
        message -> Text,
    }
}

table! {
    registered_heads (id) {
        id -> Integer,
        head -> Text,
    }
}

allow_tables_to_appear_in_same_query!(
    emails,
    registered_heads,
);
