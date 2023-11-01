use diesel::prelude::*;

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::cards)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Card {
    pub id: i32,
    pub uid: String,
    pub read_counter: i32,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::cards)]
pub struct NewCard<'a> {
    pub uid: &'a str,
    pub read_counter: i32,
}
