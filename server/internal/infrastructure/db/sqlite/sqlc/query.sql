-- name: UpsertTransaction :exec
INSERT INTO tx (
    tx, round_id, type, position, txid, tree_level, parent_txid, is_leaf
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    tx = EXCLUDED.tx,
    round_id = EXCLUDED.round_id,
    type = EXCLUDED.type,
    position = EXCLUDED.position,
    txid = EXCLUDED.txid,
    tree_level = EXCLUDED.tree_level,
    parent_txid = EXCLUDED.parent_txid,
    is_leaf = EXCLUDED.is_leaf;

-- name: UpsertRound :exec
INSERT INTO round (
    id,
    starting_timestamp,
    ending_timestamp,
    ended, failed,
    stage_code,
    txid,
    unsigned_tx,
    connector_address,
    dust_amount,
    version,
    swept
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    starting_timestamp = EXCLUDED.starting_timestamp,
    ending_timestamp = EXCLUDED.ending_timestamp,
    ended = EXCLUDED.ended,
    failed = EXCLUDED.failed,
    stage_code = EXCLUDED.stage_code,
    txid = EXCLUDED.txid,
    unsigned_tx = EXCLUDED.unsigned_tx,
    connector_address = EXCLUDED.connector_address,
    dust_amount = EXCLUDED.dust_amount,
    version = EXCLUDED.version,
    swept = EXCLUDED.swept;

-- name: UpsertPayment :exec
INSERT INTO payment (id, round_id) VALUES (?, ?)
ON CONFLICT(id) DO UPDATE SET round_id = EXCLUDED.round_id;

-- name: UpsertReceiver :exec
INSERT INTO receiver (payment_id, pubkey, amount, onchain_address) VALUES (?, ?, ?, ?)
ON CONFLICT(payment_id, pubkey) DO UPDATE SET
    amount = EXCLUDED.amount,
    onchain_address = EXCLUDED.onchain_address,
    pubkey = EXCLUDED.pubkey;

-- name: UpdateVtxoPaymentId :exec
UPDATE vtxo SET payment_id = ? WHERE txid = ? AND vout = ?;
