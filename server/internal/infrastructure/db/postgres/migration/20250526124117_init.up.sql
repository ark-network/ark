CREATE TABLE IF NOT EXISTS round (
    id VARCHAR PRIMARY KEY,
    starting_timestamp BIGINT NOT NULL,
    ending_timestamp BIGINT NOT NULL,
    ended BOOLEAN NOT NULL,
    failed BOOLEAN NOT NULL,
    stage_code INTEGER NOT NULL,
    connector_address VARCHAR NOT NULL,
    version INTEGER NOT NULL,
    swept BOOLEAN NOT NULL,
    vtxo_tree_expiration BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS tx_request (
    id VARCHAR PRIMARY KEY,
    round_id VARCHAR NOT NULL,
    FOREIGN KEY (round_id) REFERENCES round(id)
);

CREATE TABLE IF NOT EXISTS receiver (
    request_id VARCHAR NOT NULL,
    pubkey VARCHAR,
    onchain_address VARCHAR,
    amount BIGINT NOT NULL,
    FOREIGN KEY (request_id) REFERENCES tx_request(id),
    PRIMARY KEY (request_id, pubkey, onchain_address)
);

CREATE TABLE IF NOT EXISTS tx (
    txid VARCHAR PRIMARY KEY,
    tx TEXT NOT NULL,
    round_id VARCHAR NOT NULL,
    type VARCHAR NOT NULL,
    position INTEGER NOT NULL,
    tree_level INTEGER,
    parent_txid VARCHAR,
    is_leaf BOOLEAN,
    FOREIGN KEY (round_id) REFERENCES round(id)
);

CREATE TABLE IF NOT EXISTS vtxo (
    txid VARCHAR NOT NULL,
    vout INTEGER NOT NULL,
    pubkey VARCHAR NOT NULL,
    amount BIGINT NOT NULL,
    commitment_txid VARCHAR NOT NULL,
    spent_by VARCHAR NOT NULL,
    spent BOOLEAN NOT NULL,
    redeemed BOOLEAN NOT NULL,
    swept BOOLEAN NOT NULL,
    expire_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    request_id VARCHAR,
    PRIMARY KEY (txid, vout),
    FOREIGN KEY (request_id) REFERENCES tx_request(id)
);


CREATE TABLE IF NOT EXISTS market_hour (
   id SERIAL PRIMARY KEY,
   start_time BIGINT NOT NULL,
   end_time BIGINT NOT NULL,
   period BIGINT NOT NULL,
   round_interval BIGINT NOT NULL,
   updated_at BIGINT NOT NULL
);

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
    is_root_commitment_txid BOOLEAN NOT NULL DEFAULT FALSE,
    virtual_txid VARCHAR NOT NULL,
    FOREIGN KEY (virtual_txid) REFERENCES virtual_tx(txid)
);

CREATE VIEW round_request_vw AS
SELECT tx_request.*
FROM round
LEFT OUTER JOIN tx_request
ON round.id=tx_request.round_id;

CREATE VIEW round_tx_vw AS
SELECT tx.*
FROM round
LEFT OUTER JOIN tx
ON round.id=tx.round_id;

CREATE VIEW round_commitment_tx_vw AS
SELECT round.*,tx.*
FROM round
INNER JOIN tx
ON round.id=tx.round_id AND tx.type='commitment';

CREATE VIEW request_receiver_vw AS
SELECT receiver.*
FROM tx_request
LEFT OUTER JOIN receiver
ON tx_request.id=receiver.request_id;

CREATE VIEW request_vtxo_vw AS
SELECT vtxo.*
FROM tx_request
LEFT OUTER JOIN vtxo
ON tx_request.id=vtxo.request_id;

CREATE VIEW virtual_tx_checkpoint_tx_vw AS
SELECT
    virtual_tx.*,
    checkpoint_tx.txid AS checkpoint_txid,
    checkpoint_tx.tx AS checkpoint_tx,
    checkpoint_tx.commitment_txid,
    checkpoint_tx.is_root_commitment_txid,
    checkpoint_tx.virtual_txid
FROM virtual_tx
LEFT JOIN checkpoint_tx
ON virtual_tx.txid = checkpoint_tx.virtual_txid;

CREATE VIEW vtxo_virtual_tx_vw AS
SELECT
    vtxo.*,
    virtual_tx.tx AS redeem_tx
FROM vtxo
LEFT JOIN virtual_tx
ON vtxo.txid = virtual_tx.txid;