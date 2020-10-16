table! {
    django_migrations (id) {
        id -> Integer,
        app -> Text,
        name -> Text,
        applied -> Timestamp,
    }
}

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

joinable!(emails -> registered_heads (registered_head_id));

allow_tables_to_appear_in_same_query!(
    django_migrations,
    emails,
    registered_heads,
);
