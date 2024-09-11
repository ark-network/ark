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
INSERT INTO receiver (payment_id, descriptor, amount, onchain_address) VALUES (?, ?, ?, ?)
ON CONFLICT(payment_id, descriptor) DO UPDATE SET
    amount = EXCLUDED.amount,
    onchain_address = EXCLUDED.onchain_address,
    descriptor = EXCLUDED.descriptor;

-- name: UpdateVtxoPaymentId :exec
UPDATE vtxo SET payment_id = ? WHERE txid = ? AND vout = ?;

-- name: UpdateVtxoSignerPubkey :exec
UPDATE vtxo SET signer_pubkey = ? WHERE txid = ? AND vout = ?;

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

-- name: UpsertUnconditionalForfeitTx :exec
INSERT INTO uncond_forfeit_tx (tx, vtxo_txid, vtxo_vout, position)
VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET
    tx = EXCLUDED.tx,
    vtxo_txid = EXCLUDED.vtxo_txid,
    vtxo_vout = EXCLUDED.vtxo_vout,
    position = EXCLUDED.position;

-- name: UpsertVtxo :exec
INSERT INTO vtxo (txid, vout, descriptor, amount, pool_tx, spent_by, spent, redeemed, swept, expire_at, redeem_tx)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(txid, vout) DO UPDATE SET
    descriptor = EXCLUDED.descriptor,
    amount = EXCLUDED.amount,
    pool_tx = EXCLUDED.pool_tx,
    spent_by = EXCLUDED.spent_by,
    spent = EXCLUDED.spent,
    redeemed = EXCLUDED.redeemed,
    swept = EXCLUDED.swept,
    expire_at = EXCLUDED.expire_at,
    redeem_tx = EXCLUDED.redeem_tx;

-- name: SelectSweepableVtxos :many
SELECT  sqlc.embed(vtxo),
        sqlc.embed(uncond_forfeit_tx_vw)
FROM vtxo
        LEFT OUTER JOIN uncond_forfeit_tx_vw ON vtxo.txid=uncond_forfeit_tx_vw.vtxo_txid AND vtxo.vout=uncond_forfeit_tx_vw.vtxo_vout
WHERE redeemed = false AND swept = false;

-- name: SelectNotRedeemedVtxos :many
SELECT  sqlc.embed(vtxo),
        sqlc.embed(uncond_forfeit_tx_vw)
FROM vtxo
        LEFT OUTER JOIN uncond_forfeit_tx_vw ON vtxo.txid=uncond_forfeit_tx_vw.vtxo_txid AND vtxo.vout=uncond_forfeit_tx_vw.vtxo_vout
WHERE redeemed = false;

-- name: SelectNotRedeemedVtxosWithPubkey :many
SELECT  sqlc.embed(vtxo),
        sqlc.embed(uncond_forfeit_tx_vw)
FROM vtxo
        LEFT OUTER JOIN uncond_forfeit_tx_vw ON vtxo.txid=uncond_forfeit_tx_vw.vtxo_txid AND vtxo.vout=uncond_forfeit_tx_vw.vtxo_vout
WHERE redeemed = false AND INSTR(descriptor, ?) > 0;

-- name: SelectVtxoByOutpoint :one
SELECT  sqlc.embed(vtxo),
        sqlc.embed(uncond_forfeit_tx_vw)
FROM vtxo
        LEFT OUTER JOIN uncond_forfeit_tx_vw ON vtxo.txid=uncond_forfeit_tx_vw.vtxo_txid AND vtxo.vout=uncond_forfeit_tx_vw.vtxo_vout
WHERE txid = ? AND vout = ?;

-- name: SelectVtxosByPoolTxid :many
SELECT  sqlc.embed(vtxo),
        sqlc.embed(uncond_forfeit_tx_vw)
FROM vtxo
        LEFT OUTER JOIN uncond_forfeit_tx_vw ON vtxo.txid=uncond_forfeit_tx_vw.vtxo_txid AND vtxo.vout=uncond_forfeit_tx_vw.vtxo_vout
WHERE pool_tx = ?;

-- name: MarkVtxoAsRedeemed :exec
UPDATE vtxo SET redeemed = true WHERE txid = ? AND vout = ?;

-- name: MarkVtxoAsSwept :exec
UPDATE vtxo SET swept = true WHERE txid = ? AND vout = ?;

-- name: MarkVtxoAsSpent :exec
UPDATE vtxo SET spent = true, spent_by = ? WHERE txid = ? AND vout = ?;

-- name: UpdateVtxoExpireAt :exec
UPDATE vtxo SET expire_at = ? WHERE txid = ? AND vout = ?;
