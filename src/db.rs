use crate::models::{Card, NewCard};
use crate::schema::cards;
use crate::schema::cards::dsl::*;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use dotenvy::dotenv;
use std::env;

pub struct Db {
    connection: SqliteConnection,
}

impl Db {
    pub fn new() -> Self {
        dotenv().ok();

        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        Self {
            connection: SqliteConnection::establish(&database_url)
                .unwrap_or_else(|_| panic!("Error connecting to {}", database_url)),
        }
    }

    pub fn register_card(
        &mut self,
        other_uid: &str,
        other_read_counter: i32,
    ) -> Result<(), String> {
        let results: Option<Card> = cards
            .filter(uid.eq(other_uid))
            .first(&mut self.connection)
            .optional()
            .unwrap();

        match results {
            None => {
                let n = NewCard {
                    uid: other_uid,
                    read_counter: other_read_counter,
                };

                if let Ok(_) = diesel::insert_into(cards::table)
                    .values(&n)
                    .execute(&mut self.connection)
                {
                    Ok(())
                } else {
                    Err("Failed to insert row".into())
                }
            }
            Some(result) => {
                if result.read_counter >= other_read_counter {
                    Err("URI already used".into())
                } else {
                    if let Ok(_) = diesel::update(cards.find(result.id))
                        .set(read_counter.eq(other_read_counter))
                        .execute(&mut self.connection)
                    {
                        Ok(())
                    } else {
                        Err("Failed to update database".into())
                    }
                }
            }
        }
    }
}
