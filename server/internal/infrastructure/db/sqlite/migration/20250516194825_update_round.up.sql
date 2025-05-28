ALTER TABLE round DROP COLUMN dust_amount;
ALTER TABLE round DROP COLUMN unsigned_tx;
ALTER TABLE round ADD COLUMN vtxo_tree_expiration INTEGER NOT NULL;

CREATE TABLE IF NOT EXISTS virtual_tx (
    txid VARCHAR PRIMARY KEY,
    tx TEXT NOT NULL,
    starting_timestamp BIGINT NOT NULL,
    ending_timestamp BIGINT NOT NULL,
    expiry_timestamp BIGINT NOT NULL,
    fail_reason VARCHAR,
    stage_code INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoint_tx (
    txid VARCHAR PRIMARY KEY,
    tx TEXT NOT NULL,
    commitment_txid TEXT NOT NULL,
    is_root_commitment_tx BOOLEAN NOT NULL DEFAULT FALSE,
    virtual_txid VARCHAR NOT NULL,
    FOREIGN KEY (virtual_txid) REFERENCES virtual_tx(txid)
);

CREATE VIEW virtual_tx_checkpoint_tx_vw AS
SELECT
    virtual_tx.*,
    checkpoint_tx.txid AS checkpoint_txid,
    checkpoint_tx.tx AS checkpoint_tx,
    checkpoint_tx.commitment_txid,
    checkpoint_tx.is_root_commitment_tx,
    checkpoint_tx.virtual_txid
FROM virtual_tx
    INNER JOIN checkpoint_tx
    ON virtual_tx.txid = checkpoint_tx.virtual_txid;
