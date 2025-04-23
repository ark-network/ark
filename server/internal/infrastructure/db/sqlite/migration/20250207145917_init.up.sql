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

CREATE TABLE IF NOT EXISTS tx_request (
    id TEXT PRIMARY KEY,
    round_id TEXT NOT NULL,
    FOREIGN KEY (round_id) REFERENCES round(id)
);

CREATE TABLE IF NOT EXISTS receiver (
    request_id TEXT NOT NULL,
    pubkey TEXT,
    onchain_address TEXT,
    amount INTEGER NOT NULL,
    FOREIGN KEY (request_id) REFERENCES tx_request(id),
    PRIMARY KEY (request_id, pubkey, onchain_address)
);

CREATE TABLE IF NOT EXISTS tx (
    txid TEXT PRIMARY KEY,
    tx TEXT NOT NULL,
    round_id TEXT NOT NULL,
    type TEXT NOT NULL,
    position INTEGER NOT NULL,
    tree_level INTEGER,
    parent_txid TEXT,
    is_leaf BOOLEAN,
    FOREIGN KEY (round_id) REFERENCES round(id)
);

CREATE TABLE IF NOT EXISTS vtxo (
	txid TEXT NOT NULL,
	vout INTEGER NOT NULL,
	pubkey TEXT NOT NULL,
	amount INTEGER NOT NULL,
	round_tx TEXT NOT NULL,
	spent_by TEXT NOT NULL,
	spent BOOLEAN NOT NULL,
	redeemed BOOLEAN NOT NULL,
	swept BOOLEAN NOT NULL,
	expire_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
	request_id TEXT,
    redeem_tx TEXT,
    PRIMARY KEY (txid, vout),
	FOREIGN KEY (request_id) REFERENCES tx_request(id)
);

CREATE TABLE IF NOT EXISTS note (
    id INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS entity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nostr_recipient TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS entity_vtxo (
    entity_id INTEGER NOT NULL,
    vtxo_txid TEXT NOT NULL,
    vtxo_vout INTEGER NOT NULL,
    FOREIGN KEY (entity_id) REFERENCES entity(id),
    PRIMARY KEY (entity_id, vtxo_txid, vtxo_vout)
);

CREATE TABLE IF NOT EXISTS market_hour (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   start_time INTEGER NOT NULL,
   end_time INTEGER NOT NULL,
   period INTEGER NOT NULL,
   round_interval INTEGER NOT NULL,
   updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_round_txid ON round(txid);

CREATE VIEW IF NOT EXISTS entity_vw AS
SELECT entity.id, entity.nostr_recipient, entity_vtxo.vtxo_txid, entity_vtxo.vtxo_vout
FROM entity
LEFT OUTER JOIN entity_vtxo
ON entity.id=entity_vtxo.entity_id;

CREATE VIEW IF NOT EXISTS round_request_vw AS
SELECT tx_request.*
FROM round
LEFT OUTER JOIN tx_request
ON round.id=tx_request.round_id;

CREATE VIEW IF NOT EXISTS round_tx_vw AS
SELECT tx.*
FROM round
LEFT OUTER JOIN tx
ON round.id=tx.round_id;

CREATE VIEW IF NOT EXISTS request_receiver_vw AS
SELECT receiver.*
FROM tx_request
LEFT OUTER JOIN receiver
ON tx_request.id=receiver.request_id;

CREATE VIEW IF NOT EXISTS request_vtxo_vw AS
SELECT vtxo.*
FROM tx_request
LEFT OUTER JOIN vtxo
ON tx_request.id=vtxo.request_id;