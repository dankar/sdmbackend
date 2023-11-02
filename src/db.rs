use crate::models::{Card, NewCard, NewVisit};
use crate::schema::cards;
use crate::schema::visits;
use crate::schema::cards::dsl::*;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use log::{debug, error};
use std::env;

pub struct Db {
    connection: SqliteConnection,
}

impl Db {
    pub fn new() -> Self {
        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        Self {
            connection: SqliteConnection::establish(&database_url)
                .unwrap_or_else(|_| panic!("Error connecting to {}", database_url)),
        }
    }

    pub fn get_card(&mut self, other_uid: &str) -> Option<Card> {
        cards
            .filter(uid.eq(other_uid))
            .first(&mut self.connection)
            .optional()
            .unwrap()
    }

    pub fn register_visit(&mut self, other_uid: &str) -> Result<(), String> {
        let visit_card_id = match self.get_card(other_uid) {
            Some(result) => result.id,
            None => return Err("Card does not exist".into()),
        };

        if let Ok(_) = diesel::insert_into(visits::table).values(&NewVisit { card_id: visit_card_id }).execute(&mut self.connection) {
            Ok(())
        } else {
            Err("Failed to insert visit".into())
        }
    }

    pub fn register_card(
        &mut self,
        other_uid: &str,
        other_read_counter: i32,
    ) -> Result<(), String> {
        match self.get_card(other_uid) {
            Some(result) => {
                if result.read_counter >= other_read_counter {
                    error!("Duplicate/old read counter for card '{}'", other_uid);
                    return Err("URI already used".into());
                } else {
                    if let Ok(_) = diesel::update(cards.find(result.id))
                        .set(read_counter.eq(other_read_counter))
                        .execute(&mut self.connection)
                    {
                        debug!("Granted access to card '{}'", other_uid);
                    } else {
                        error!("Failed to update read counter for card '{}'", other_uid);
                        return Err("Failed to update database".into());
                    }
                }
            }
            None => {
                let n = NewCard {
                    uid: other_uid,
                    read_counter: other_read_counter,
                };

                if let Ok(_) = diesel::insert_into(cards::table)
                    .values(&n)
                    .execute(&mut self.connection)
                {
                    debug!("First visit for card '{}'", other_uid);
                } else {
                    error!("Failed to insert row for card '{}'", other_uid);
                    return Err("Failed to insert row".into());
                }
            }
        };

        return self.register_visit(other_uid);
    }
}
