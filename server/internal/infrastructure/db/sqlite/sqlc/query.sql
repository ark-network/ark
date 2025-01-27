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

-- name: UpsertTxRequest :exec
INSERT INTO tx_request (id, round_id) VALUES (?, ?)
ON CONFLICT(id) DO UPDATE SET round_id = EXCLUDED.round_id;

-- name: UpsertReceiver :exec
INSERT INTO receiver (request_id, pubkey, onchain_address, amount) VALUES (?, ?, ?, ?)
ON CONFLICT(request_id, pubkey, onchain_address) DO UPDATE SET
    amount = EXCLUDED.amount,
    pubkey = EXCLUDED.pubkey,
    onchain_address = EXCLUDED.onchain_address;

-- name: UpdateVtxoRequestId :exec
UPDATE vtxo SET request_id = ? WHERE txid = ? AND vout = ?;

-- name: SelectRoundWithRoundId :many
SELECT sqlc.embed(round),
       sqlc.embed(round_request_vw),
       sqlc.embed(round_tx_vw),
       sqlc.embed(request_receiver_vw),
       sqlc.embed(request_vtxo_vw)
FROM round
         LEFT OUTER JOIN round_request_vw ON round.id=round_request_vw.round_id
         LEFT OUTER JOIN round_tx_vw ON round.id=round_tx_vw.round_id
         LEFT OUTER JOIN request_receiver_vw ON round_request_vw.id=request_receiver_vw.request_id
         LEFT OUTER JOIN request_vtxo_vw ON round_request_vw.id=request_vtxo_vw.request_id
WHERE round.id = ?;

-- name: SelectRoundWithRoundTxId :many
SELECT sqlc.embed(round),
       sqlc.embed(round_request_vw),
       sqlc.embed(round_tx_vw),
       sqlc.embed(request_receiver_vw),
       sqlc.embed(request_vtxo_vw)
FROM round
         LEFT OUTER JOIN round_request_vw ON round.id=round_request_vw.round_id
         LEFT OUTER JOIN round_tx_vw ON round.id=round_tx_vw.round_id
         LEFT OUTER JOIN request_receiver_vw ON round_request_vw.id=request_receiver_vw.request_id
         LEFT OUTER JOIN request_vtxo_vw ON round_request_vw.id=request_vtxo_vw.request_id
WHERE round.txid = ?;

-- name: SelectExpiredRoundsTxid :many
SELECT round.txid FROM round
WHERE round.swept = false AND round.ended = true AND round.failed = false;

-- name: SelectSweptRoundsConnectorAddress :many
SELECT round.connector_address FROM round
WHERE round.swept = true AND round.failed = false AND round.ended = true AND round.connector_address <> '';

-- name: SelectRoundIdsInRange :many
SELECT id FROM round WHERE starting_timestamp > ? AND starting_timestamp < ?;

-- name: SelectRoundIds :many
SELECT id FROM round;

-- name: UpsertVtxo :exec
INSERT INTO vtxo (txid, vout, pubkey, amount, round_tx, spent_by, spent, redeemed, swept, expire_at, created_at, redeem_tx)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(txid, vout) DO UPDATE SET
    pubkey = EXCLUDED.pubkey,
    amount = EXCLUDED.amount,
    round_tx = EXCLUDED.round_tx,
    spent_by = EXCLUDED.spent_by,
    spent = EXCLUDED.spent,
    redeemed = EXCLUDED.redeemed,
    swept = EXCLUDED.swept,
    expire_at = EXCLUDED.expire_at,
    created_at = EXCLUDED.created_at,
    redeem_tx = EXCLUDED.redeem_tx;

-- name: SelectSweepableVtxos :many
SELECT sqlc.embed(vtxo) FROM vtxo
WHERE redeemed = false AND swept = false;

-- name: SelectNotRedeemedVtxos :many
SELECT sqlc.embed(vtxo) FROM vtxo
WHERE redeemed = false;

-- name: SelectNotRedeemedVtxosWithPubkey :many
SELECT sqlc.embed(vtxo) FROM vtxo
WHERE redeemed = false AND pubkey = ?;

-- name: SelectVtxoByOutpoint :one
SELECT sqlc.embed(vtxo) FROM vtxo
WHERE txid = ? AND vout = ?;

-- name: SelectVtxosByRoundTxid :many
SELECT sqlc.embed(vtxo) FROM vtxo
WHERE round_tx = ?;

-- name: MarkVtxoAsRedeemed :exec
UPDATE vtxo SET redeemed = true WHERE txid = ? AND vout = ?;

-- name: MarkVtxoAsSwept :exec
UPDATE vtxo SET swept = true WHERE txid = ? AND vout = ?;

-- name: MarkVtxoAsSpent :exec
UPDATE vtxo SET spent = true, spent_by = ? WHERE txid = ? AND vout = ?;

-- name: UpdateVtxoExpireAt :exec
UPDATE vtxo SET expire_at = ? WHERE txid = ? AND vout = ?;

-- name: UpsertEntity :one
INSERT INTO entity (nostr_recipient)
VALUES (?)
ON CONFLICT(nostr_recipient) DO UPDATE SET
    nostr_recipient = EXCLUDED.nostr_recipient
RETURNING id;

-- name: UpsertEntityVtxo :exec
INSERT INTO entity_vtxo (entity_id, vtxo_txid, vtxo_vout)
VALUES (?, ?, ?)
ON CONFLICT(entity_id, vtxo_txid, vtxo_vout) DO UPDATE SET
    entity_id = EXCLUDED.entity_id;

-- name: SelectEntitiesByVtxo :many
SELECT sqlc.embed(entity_vw) FROM entity_vw
WHERE vtxo_txid = ? AND vtxo_vout = ?;

-- name: DeleteEntityVtxo :exec
DELETE FROM entity_vtxo WHERE entity_id = ?;

-- name: DeleteEntity :exec
DELETE FROM entity WHERE id = ?;

-- name: InsertNote :exec
INSERT INTO note (id) VALUES (?);

-- name: ContainsNote :one
SELECT EXISTS(SELECT 1 FROM note WHERE id = ?);

-- name: InsertMarketHour :one
INSERT INTO market_hour (
    start_time,
    end_time,
    period,
    round_interval,
    updated_at
) VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateMarketHour :one
UPDATE market_hour
SET start_time = ?,
    end_time = ?,
    period = ?,
    round_interval = ?,
    updated_at = ?
WHERE id = ?
RETURNING *;

-- name: GetLatestMarketHour :one
SELECT * FROM market_hour ORDER BY updated_at DESC LIMIT 1;

-- name: SelectTreeTxsWithRoundTxid :many
SELECT tx.* FROM round
LEFT OUTER JOIN tx ON round.id=tx.round_id
WHERE round.txid = ? AND tx.type = 'tree'
