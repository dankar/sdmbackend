use diesel::prelude::*;

#[derive(Identifiable, Queryable, Selectable)]
#[diesel(table_name = crate::schema::cards)]
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

#[derive(Identifiable, Queryable, Associations, PartialEq, Debug)]
#[diesel(belongs_to(Card))]
#[diesel(table_name = crate::schema::visits)]
pub struct Visit {
    id: i32,
    card_id: i32,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::visits)]
pub struct NewVisit {
    pub card_id: i32,
}
