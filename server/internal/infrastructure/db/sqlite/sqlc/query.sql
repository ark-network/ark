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

-- name: SelectRoundWithRoundId :many
SELECT sqlc.embed(round), sqlc.embed(payment), sqlc.embed(tx), sqlc.embed(receiver), sqlc.embed(vtxo)
FROM round
     LEFT OUTER JOIN payment ON round.id=payment.round_id
     LEFT OUTER JOIN tx ON round.id=tx.round_id
     LEFT OUTER JOIN receiver ON payment.id=receiver.payment_id
     LEFT OUTER JOIN vtxo ON payment.id=vtxo.payment_id
WHERE round.id = ?;

-- name: SelectRoundWithRoundTxId :many
SELECT sqlc.embed(round), sqlc.embed(payment), sqlc.embed(tx), sqlc.embed(receiver), sqlc.embed(vtxo)
FROM round
    LEFT OUTER JOIN payment ON round.id=payment.round_id
    LEFT OUTER JOIN tx ON round.id=tx.round_id
    LEFT OUTER JOIN receiver ON payment.id=receiver.payment_id
    LEFT OUTER JOIN vtxo ON payment.id=vtxo.payment_id
WHERE round.txid = ?;

-- name: SelectSweepableRounds :many
SELECT sqlc.embed(round), sqlc.embed(payment), sqlc.embed(tx), sqlc.embed(receiver), sqlc.embed(vtxo)
FROM round
     LEFT OUTER JOIN payment ON round.id=payment.round_id
     LEFT OUTER JOIN tx ON round.id=tx.round_id
     LEFT OUTER JOIN receiver ON payment.id=receiver.payment_id
     LEFT OUTER JOIN vtxo ON payment.id=vtxo.payment_id
WHERE round.swept = false AND round.ended = true AND round.failed = false;

-- name: SelectSweptRounds :many
SELECT sqlc.embed(round), sqlc.embed(payment), sqlc.embed(tx), sqlc.embed(receiver), sqlc.embed(vtxo)
FROM round
     LEFT OUTER JOIN payment ON round.id=payment.round_id
     LEFT OUTER JOIN tx ON round.id=tx.round_id
     LEFT OUTER JOIN receiver ON payment.id=receiver.payment_id
     LEFT OUTER JOIN vtxo ON payment.id=vtxo.payment_id
WHERE round.swept = true AND round.failed = false AND round.ended = true AND round.connector_address <> '';

-- name: SelectRoundIdsInRange :many
SELECT id FROM round WHERE starting_timestamp > ? AND starting_timestamp < ?;

-- name: SelectRoundIds :many
SELECT id FROM round;

-- name: UpsertVtxo :exec
INSERT INTO vtxo (txid, vout, pubkey, amount, pool_tx, spent_by, spent, redeemed, swept, expire_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(txid) DO UPDATE SET
    vout = excluded.vout,
    pubkey = excluded.pubkey,
    amount = excluded.amount,
    pool_tx = excluded.pool_tx,
    spent_by = excluded.spent_by,
    spent = excluded.spent,
    redeemed = excluded.redeemed,
    swept = excluded.swept,
    expire_at = excluded.expire_at;

-- name: SelectSweepableVtxos :many
SELECT * FROM vtxo WHERE redeemed = false AND swept = false;

-- name: SelectNotRedeemedVtxos :many
SELECT * FROM vtxo WHERE redeemed = false;

-- name: SelectNotRedeemedVtxosWithPubkey :many
SELECT * FROM vtxo WHERE redeemed = false AND pubkey = ?;

-- name: SelectVtxoByOutpoint :one
SELECT * FROM vtxo WHERE txid = ? AND vout = ?;

-- name: SelectVtxosByPoolTxid :many
SELECT * FROM vtxo WHERE pool_tx = ?;

-- name: MarkVtxoAsRedeemed :exec
UPDATE vtxo SET redeemed = true WHERE txid = ? AND vout = ?;

-- name: MarkVtxoAsSwept :exec
UPDATE vtxo SET swept = true WHERE txid = ? AND vout = ?;

-- name: MarkVtxoAsSpent :exec
UPDATE vtxo SET spent = true, spent_by = ? WHERE txid = ? AND vout = ?;

-- name: UpdateVtxoExpireAt :exec
UPDATE vtxo SET expire_at = ? WHERE txid = ? AND vout = ?;
