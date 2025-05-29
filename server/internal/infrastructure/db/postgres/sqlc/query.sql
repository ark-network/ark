-- name: UpsertTransaction :exec
INSERT INTO tx (
    tx, round_id, type, position, txid, tree_level, parent_txid, is_leaf
) VALUES (@tx, @round_id, @type, @position, @txid, @tree_level, @parent_txid, @is_leaf)
    ON CONFLICT(txid) DO UPDATE SET
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
    connector_address,
    version,
    swept,
    vtxo_tree_expiration
) VALUES (@id, @starting_timestamp, @ending_timestamp, @ended, @failed, @stage_code, @txid, @connector_address, @version, @swept, @vtxo_tree_expiration)
    ON CONFLICT(id) DO UPDATE SET
    starting_timestamp = EXCLUDED.starting_timestamp,
                           ending_timestamp = EXCLUDED.ending_timestamp,
                           ended = EXCLUDED.ended,
                           failed = EXCLUDED.failed,
                           stage_code = EXCLUDED.stage_code,
                           txid = EXCLUDED.txid,
                           connector_address = EXCLUDED.connector_address,
                           version = EXCLUDED.version,
                           swept = EXCLUDED.swept,
                           vtxo_tree_expiration = EXCLUDED.vtxo_tree_expiration;


-- name: GetTxsByTxid :many
SELECT
    tx.txid,
    tx.tx AS data
FROM tx
WHERE tx.txid = ANY($1::varchar[])
UNION
SELECT
    vtxo.txid,
    vtxo.redeem_tx AS data
FROM vtxo
WHERE vtxo.txid = ANY($2::varchar[]) AND vtxo.redeem_tx IS NOT NULL AND vtxo.redeem_tx <> '';

-- name: UpsertTxRequest :exec
INSERT INTO tx_request (id, round_id) VALUES (@id, @round_id)
    ON CONFLICT(id) DO UPDATE SET round_id = EXCLUDED.round_id;

-- name: UpsertReceiver :exec
INSERT INTO receiver (request_id, pubkey, onchain_address, amount) VALUES (@request_id, @pubkey, @onchain_address, @amount)
    ON CONFLICT(request_id, pubkey, onchain_address) DO UPDATE SET
    amount = EXCLUDED.amount,
    pubkey = EXCLUDED.pubkey,
    onchain_address = EXCLUDED.onchain_address;

-- name: UpdateVtxoRequestId :exec
UPDATE vtxo SET request_id = @request_id WHERE txid = @txid AND vout = @vout;

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
WHERE round.id = @id;

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
WHERE round.txid = @txid;

-- name: SelectExpiredRoundsTxid :many
SELECT round.txid FROM round
WHERE round.swept = false AND round.ended = true AND round.failed = false;

-- name: GetRoundStats :one
SELECT
    r.swept,
    r.starting_timestamp,
    r.ending_timestamp,
    (
        SELECT COALESCE(SUM(amount), 0)
        FROM (
                 SELECT DISTINCT v2.*
                 FROM vtxo v2
                          JOIN tx_request req2 ON req2.id = v2.request_id
                 WHERE req2.round_id = r.id
             ) as tx_req_inputs_amount
    ) AS total_forfeit_amount,
    (
        SELECT COALESCE(COUNT(v3.txid), 0)
        FROM vtxo v3
                 JOIN tx_request req3 ON req3.id = v3.request_id
        WHERE req3.round_id = r.id
    ) AS total_input_vtxos,
    (
        SELECT COALESCE(SUM(amount), 0)
        FROM (
                 SELECT DISTINCT rr.*
                 FROM receiver rr
                          JOIN tx_request req4 ON req4.id = rr.request_id
                 WHERE req4.round_id = r.id
                   AND (rr.onchain_address = '' OR rr.onchain_address IS NULL)
             ) AS tx_req_outputs_amount
    ) AS total_batch_amount,
    (
        SELECT COUNT(*)
        FROM tx t
        WHERE t.round_id = r.id
          AND t.type = 'tree'
          AND t.is_leaf = 1
    ) AS total_output_vtxos,
    (
        SELECT MAX(v.expire_at)
        FROM vtxo v
        WHERE v.round_tx = r.txid
    ) AS expires_at
FROM round r
WHERE r.txid = @txid;

-- name: GetRoundForfeitTxs :many
SELECT tx.* FROM round
                     LEFT OUTER JOIN tx ON round.id=tx.round_id
WHERE round.txid = @txid AND tx.type = 'forfeit';

-- name: GetRoundConnectorTreeTxs :many
SELECT tx.* FROM round
                     LEFT OUTER JOIN tx ON round.id=tx.round_id
WHERE round.txid = @txid AND tx.type = 'connector';

-- name: GetSpendableVtxosWithPubKey :many
SELECT vtxo.* FROM vtxo
WHERE vtxo.pubkey = @pubkey AND vtxo.spent = false AND vtxo.swept = false;

-- name: SelectSweptRoundsConnectorAddress :many
SELECT round.connector_address FROM round
WHERE round.swept = true AND round.failed = false AND round.ended = true AND round.connector_address <> '';

-- name: SelectRoundIdsInRange :many
SELECT id FROM round WHERE starting_timestamp > @start_ts AND starting_timestamp < @end_ts;

-- name: SelectRoundIds :many
SELECT id FROM round;

-- name: UpsertVtxo :exec
INSERT INTO vtxo (txid, vout, pubkey, amount, round_tx, spent_by, spent, redeemed, swept, expire_at, created_at, redeem_tx)
VALUES (@txid, @vout, @pubkey, @amount, @round_tx, @spent_by, @spent, @redeemed, @swept, @expire_at, @created_at, @redeem_tx) ON CONFLICT(txid, vout) DO UPDATE SET
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
WHERE redeemed = false AND pubkey = @pubkey;

-- name: SelectVtxoByOutpoint :one
SELECT sqlc.embed(vtxo) FROM vtxo
WHERE txid = @txid AND vout = @vout;

-- name: SelectAllVtxos :many
SELECT sqlc.embed(vtxo) FROM vtxo;

-- name: SelectVtxosByRoundTxid :many
SELECT sqlc.embed(vtxo) FROM vtxo
WHERE round_tx = @round_tx;

-- name: MarkVtxoAsRedeemed :exec
UPDATE vtxo SET redeemed = true WHERE txid = @txid AND vout = @vout;

-- name: MarkVtxoAsSwept :exec
UPDATE vtxo SET swept = true WHERE txid = @txid AND vout = @vout;

-- name: MarkVtxoAsSpent :exec
UPDATE vtxo SET spent = true, spent_by = @spent_by WHERE txid = @txid AND vout = @vout;

-- name: UpdateVtxoExpireAt :exec
UPDATE vtxo SET expire_at = @expire_at WHERE txid = @txid AND vout = @vout;

-- name: InsertMarketHour :one
INSERT INTO market_hour (
    start_time,
    end_time,
    period,
    round_interval,
    updated_at
) VALUES (@start_time, @end_time, @period, @round_interval, @updated_at)
    RETURNING *;

-- name: UpdateMarketHour :one
UPDATE market_hour
SET start_time = @start_time,
    end_time = @end_time,
    period = @period,
    round_interval = @round_interval,
    updated_at = @updated_at
WHERE id = @id
    RETURNING *;

-- name: GetLatestMarketHour :one
SELECT * FROM market_hour ORDER BY updated_at DESC LIMIT 1;

-- name: SelectTreeTxsWithRoundTxid :many
SELECT tx.* FROM round
                     LEFT OUTER JOIN tx ON round.id=tx.round_id
WHERE round.txid = @txid AND tx.type = 'tree';

-- name: SelectVtxosWithPubkey :many
SELECT sqlc.embed(vtxo) FROM vtxo WHERE pubkey = @pubkey;

-- name: GetExistingRounds :many
SELECT txid FROM round WHERE txid = ANY($1::varchar[]);

-- name: SelectLeafVtxosByRoundTxid :many
SELECT sqlc.embed(vtxo) FROM vtxo
WHERE round_tx = @round_tx AND (redeem_tx IS NULL or redeem_tx = '');

-- name: UpsertVirtualTx :exec
INSERT INTO virtual_tx (
    txid, tx, starting_timestamp, ending_timestamp, expiry_timestamp, fail_reason, stage_code
) VALUES (@txid, @tx, @starting_timestamp, @ending_timestamp, @expiry_timestamp, @fail_reason, @stage_code)
    ON CONFLICT(txid) DO UPDATE SET
    tx = EXCLUDED.tx,
    starting_timestamp = EXCLUDED.starting_timestamp,
    ending_timestamp = EXCLUDED.ending_timestamp,
    expiry_timestamp = EXCLUDED.expiry_timestamp,
    fail_reason = EXCLUDED.fail_reason,
    stage_code = EXCLUDED.stage_code;

-- name: UpsertCheckpointTx :exec
INSERT INTO checkpoint_tx (
    txid, tx, commitment_txid, is_root_commitment_tx, virtual_txid
) VALUES (@txid, @tx, @commitment_txid, @is_root_commitment_tx, @virtual_txid)
    ON CONFLICT(txid) DO UPDATE SET
    tx = EXCLUDED.tx,
    commitment_txid = EXCLUDED.commitment_txid,
    is_root_commitment_tx = EXCLUDED.is_root_commitment_tx,
    virtual_txid = EXCLUDED.virtual_txid;

-- name: SelectVirtualTxWithTxId :many
SELECT  sqlc.embed(virtual_tx_checkpoint_tx_vw)
FROM virtual_tx_checkpoint_tx_vw WHERE txid = @txid;