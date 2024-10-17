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
INSERT INTO receiver (payment_id, addr, amount) VALUES (?, ?, ?)
ON CONFLICT(payment_id, addr) DO UPDATE SET
    amount = EXCLUDED.amount,
    addr = EXCLUDED.addr;

-- name: UpdateVtxoPaymentId :exec
UPDATE vtxo SET payment_id = ? WHERE txid = ? AND vout = ?;

-- name: SelectRoundWithRoundId :many
SELECT sqlc.embed(round),
       sqlc.embed(round_payment_vw),
       sqlc.embed(round_tx_vw),
       sqlc.embed(payment_receiver_vw),
       sqlc.embed(payment_vtxo_vw)
FROM round
         LEFT OUTER JOIN round_payment_vw ON round.id=round_payment_vw.round_id
         LEFT OUTER JOIN round_tx_vw ON round.id=round_tx_vw.round_id
         LEFT OUTER JOIN payment_receiver_vw ON round_payment_vw.id=payment_receiver_vw.payment_id
         LEFT OUTER JOIN payment_vtxo_vw ON round_payment_vw.id=payment_vtxo_vw.payment_id
WHERE round.id = ?;

-- name: SelectRoundWithRoundTxId :many
SELECT sqlc.embed(round),
       sqlc.embed(round_payment_vw),
       sqlc.embed(round_tx_vw),
       sqlc.embed(payment_receiver_vw),
       sqlc.embed(payment_vtxo_vw)
FROM round
         LEFT OUTER JOIN round_payment_vw ON round.id=round_payment_vw.round_id
         LEFT OUTER JOIN round_tx_vw ON round.id=round_tx_vw.round_id
         LEFT OUTER JOIN payment_receiver_vw ON round_payment_vw.id=payment_receiver_vw.payment_id
         LEFT OUTER JOIN payment_vtxo_vw ON round_payment_vw.id=payment_vtxo_vw.payment_id
WHERE round.txid = ?;

-- name: SelectSweepableRounds :many
SELECT sqlc.embed(round),
       sqlc.embed(round_payment_vw),
       sqlc.embed(round_tx_vw),
       sqlc.embed(payment_receiver_vw),
       sqlc.embed(payment_vtxo_vw)
FROM round
         LEFT OUTER JOIN round_payment_vw ON round.id=round_payment_vw.round_id
         LEFT OUTER JOIN round_tx_vw ON round.id=round_tx_vw.round_id
         LEFT OUTER JOIN payment_receiver_vw ON round_payment_vw.id=payment_receiver_vw.payment_id
         LEFT OUTER JOIN payment_vtxo_vw ON round_payment_vw.id=payment_vtxo_vw.payment_id
WHERE round.swept = false AND round.ended = true AND round.failed = false;

-- name: SelectSweptRounds :many
SELECT sqlc.embed(round),
       sqlc.embed(round_payment_vw),
       sqlc.embed(round_tx_vw),
       sqlc.embed(payment_receiver_vw),
       sqlc.embed(payment_vtxo_vw)
FROM round
         LEFT OUTER JOIN round_payment_vw ON round.id=round_payment_vw.round_id
         LEFT OUTER JOIN round_tx_vw ON round.id=round_tx_vw.round_id
         LEFT OUTER JOIN payment_receiver_vw ON round_payment_vw.id=payment_receiver_vw.payment_id
         LEFT OUTER JOIN payment_vtxo_vw ON round_payment_vw.id=payment_vtxo_vw.payment_id
WHERE round.swept = true AND round.failed = false AND round.ended = true AND round.connector_address <> '';

-- name: SelectRoundIdsInRange :many
SELECT id FROM round WHERE starting_timestamp > ? AND starting_timestamp < ?;

-- name: SelectRoundIds :many
SELECT id FROM round;

-- name: UpsertVtxo :exec
INSERT INTO vtxo (txid, vout, addr, amount, pool_tx, spent_by, spent, redeemed, swept, expire_at, redeem_tx, pending)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(txid, vout) DO UPDATE SET
    addr = EXCLUDED.addr,
    amount = EXCLUDED.amount,
    pool_tx = EXCLUDED.pool_tx,
    spent_by = EXCLUDED.spent_by,
    spent = EXCLUDED.spent,
    redeemed = EXCLUDED.redeemed,
    swept = EXCLUDED.swept,
    expire_at = EXCLUDED.expire_at,
    redeem_tx = EXCLUDED.redeem_tx,
    pending = EXCLUDED.pending;

-- name: SelectSweepableVtxos :many
SELECT sqlc.embed(vtxo) FROM vtxo
WHERE redeemed = false AND swept = false;

-- name: SelectNotRedeemedVtxos :many
SELECT sqlc.embed(vtxo) FROM vtxo
WHERE redeemed = false;

-- name: SelectNotRedeemedVtxosWithAddress :many
SELECT sqlc.embed(vtxo) FROM vtxo
WHERE redeemed = false AND addr = ?;

-- name: SelectVtxoByOutpoint :one
SELECT sqlc.embed(vtxo) FROM vtxo
WHERE txid = ? AND vout = ?;

-- name: SelectVtxosByPoolTxid :many
SELECT sqlc.embed(vtxo) FROM vtxo
WHERE pool_tx = ?;

-- name: MarkVtxoAsRedeemed :exec
UPDATE vtxo SET redeemed = true WHERE txid = ? AND vout = ?;

-- name: MarkVtxoAsSwept :exec
UPDATE vtxo SET swept = true WHERE txid = ? AND vout = ?;

-- name: MarkVtxoAsSpent :exec
UPDATE vtxo SET spent = true, spent_by = ? WHERE txid = ? AND vout = ?;

-- name: UpdateVtxoExpireAt :exec
UPDATE vtxo SET expire_at = ? WHERE txid = ? AND vout = ?;
