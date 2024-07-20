CREATE TABLE IF NOT EXISTS round (
    id TEXT PRIMARY KEY,
    starting_timestamp INTEGER NOT NULL,
    ending_timestamp INTEGER NOT NULL,
    ended BOOLEAN NOT NULL,
    failed BOOLEAN NOT NULL,
    stage_code INTEGER NOT NULL,
    txid TEXT NOT NULL,
    unsigned_tx TEXT NOT NULL,
    connector_address TEXT NOT NULL,
    dust_amount INTEGER NOT NULL,
    version INTEGER NOT NULL,
    swept BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS payment (
    id TEXT PRIMARY KEY,
    round_id TEXT NOT NULL,
    FOREIGN KEY (round_id) REFERENCES round(id)
);

CREATE TABLE IF NOT EXISTS receiver (
    payment_id TEXT NOT NULL,
    pubkey TEXT NOT NULL,
    amount INTEGER NOT NULL,
    onchain_address TEXT NOT NULL,
    FOREIGN KEY (payment_id) REFERENCES payment(id),
    PRIMARY KEY (payment_id, pubkey)
);

CREATE TABLE IF NOT EXISTS tx (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx TEXT NOT NULL,
    round_id TEXT NOT NULL,
    type TEXT NOT NULL,
    position INTEGER NOT NULL,
    txid TEXT,
    tree_level INTEGER,
    parent_txid TEXT,
    is_leaf BOOLEAN,
    FOREIGN KEY (round_id) REFERENCES round(id)
);

CREATE TABLE IF NOT EXISTS vtxo (
	txid TEXT NOT NULL PRIMARY KEY,
	vout INTEGER NOT NULL,
	pubkey TEXT NOT NULL,
	amount INTEGER NOT NULL,
	pool_tx TEXT NOT NULL,
	spent_by TEXT NOT NULL,
	spent BOOLEAN NOT NULL,
	redeemed BOOLEAN NOT NULL,
	swept BOOLEAN NOT NULL,
	expire_at INTEGER NOT NULL,
	payment_id TEXT,
	FOREIGN KEY (payment_id) REFERENCES payment(id)
);