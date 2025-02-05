CREATE TABLE IF NOT EXISTS vtxo_tree_keys (
    round_id TEXT NOT NULL,
    pubkey BLOB NOT NULL,
    seckey BLOB,
    PRIMARY KEY (round_id, pubkey)
);
