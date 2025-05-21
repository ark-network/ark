ALTER TABLE round DROP COLUMN dust_amount;
ALTER TABLE round DROP COLUMN unsigned_tx;
ALTER TABLE round ADD COLUMN vtxo_tree_expiration INTEGER NOT NULL;

CREATE TABLE IF NOT EXISTS offchain_tx (
    txid TEXT PRIMARY KEY NOT NULL,
    starting_timestamp INTEGER NOT NULL,
    ending_timestamp INTEGER NOT NULL,
    expiry_timestamp INTEGER NOT NULL,
    fail_reason TEXT,
    stage_code INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS virtual_tx (
    txid TEXT PRIMARY KEY,
    tx TEXT NOT NULL,
    offchain_txid TEXT NOT NULL,
    type TEXT NOT NULL,
    position INTEGER NOT NULL,
    FOREIGN KEY (offchain_txid) REFERENCES offchain_tx(txid)
);

CREATE VIEW IF NOT EXISTS offchain_tx_virtual_tx_vw AS
SELECT virtual_tx.*
FROM offchain_tx
LEFT OUTER JOIN virtual_tx
ON offchain_tx.txid=virtual_tx.offchain_txid;