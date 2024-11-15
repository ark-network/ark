CREATE TABLE IF NOT EXISTS market_hour (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   first_market_hour INTEGER NOT NULL,
   period INTEGER NOT NULL,
   round_lifetime INTEGER NOT NULL,
   created_at INTEGER NOT NULL
);
