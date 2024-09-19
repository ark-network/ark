CREATE TABLE IF NOT EXISTS txs (
    id TEXT PRIMARY KEY,
    boarding_txid TEXT NOT NULL,
    round_txid TEXT NOT NULL,
    redeem_txid TEXT NOT NULL,
    amount INTEGER NOT NULL,
    type TEXT NOT NULL,
    pending BOOLEAN NOT NULL,
    claimed BOOLEAN NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE vtxo (
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    round_txid TEXT,
    expires_at TIMESTAMP,
    redeem_tx TEXT,
    unconditional_forfeit_txs TEXT,
    pending BOOLEAN,
    spent_by TEXT,
    spent BOOLEAN,
    PRIMARY KEY (txid, vout)
);