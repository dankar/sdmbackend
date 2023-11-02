CREATE TABLE visits(
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  card_id INTEGER,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(card_id) REFERENCES cards(id)
);
