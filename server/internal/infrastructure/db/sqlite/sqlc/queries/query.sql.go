// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: query.sql

package queries

import (
	"context"
	"database/sql"
)

const markVtxoAsRedeemed = `-- name: MarkVtxoAsRedeemed :exec
UPDATE vtxo SET redeemed = true WHERE txid = ? AND vout = ?
`

type MarkVtxoAsRedeemedParams struct {
	Txid string
	Vout int64
}

func (q *Queries) MarkVtxoAsRedeemed(ctx context.Context, arg MarkVtxoAsRedeemedParams) error {
	_, err := q.db.ExecContext(ctx, markVtxoAsRedeemed, arg.Txid, arg.Vout)
	return err
}

const markVtxoAsSpent = `-- name: MarkVtxoAsSpent :exec
UPDATE vtxo SET spent = true, spent_by = ? WHERE txid = ? AND vout = ?
`

type MarkVtxoAsSpentParams struct {
	SpentBy string
	Txid    string
	Vout    int64
}

func (q *Queries) MarkVtxoAsSpent(ctx context.Context, arg MarkVtxoAsSpentParams) error {
	_, err := q.db.ExecContext(ctx, markVtxoAsSpent, arg.SpentBy, arg.Txid, arg.Vout)
	return err
}

const markVtxoAsSwept = `-- name: MarkVtxoAsSwept :exec
UPDATE vtxo SET swept = true WHERE txid = ? AND vout = ?
`

type MarkVtxoAsSweptParams struct {
	Txid string
	Vout int64
}

func (q *Queries) MarkVtxoAsSwept(ctx context.Context, arg MarkVtxoAsSweptParams) error {
	_, err := q.db.ExecContext(ctx, markVtxoAsSwept, arg.Txid, arg.Vout)
	return err
}

const selectNotRedeemedVtxos = `-- name: SelectNotRedeemedVtxos :many
SELECT  vtxo.txid, vtxo.vout, vtxo.amount, vtxo.pool_tx, vtxo.spent_by, vtxo.spent, vtxo.redeemed, vtxo.swept, vtxo.expire_at, vtxo.payment_id, vtxo.redeem_tx, vtxo.descriptor, vtxo.pending_change,
        uncond_forfeit_tx_vw.id, uncond_forfeit_tx_vw.tx, uncond_forfeit_tx_vw.vtxo_txid, uncond_forfeit_tx_vw.vtxo_vout, uncond_forfeit_tx_vw.position
FROM vtxo
        LEFT OUTER JOIN uncond_forfeit_tx_vw ON vtxo.txid=uncond_forfeit_tx_vw.vtxo_txid AND vtxo.vout=uncond_forfeit_tx_vw.vtxo_vout
WHERE redeemed = false
`

type SelectNotRedeemedVtxosRow struct {
	Vtxo              Vtxo
	UncondForfeitTxVw UncondForfeitTxVw
}

func (q *Queries) SelectNotRedeemedVtxos(ctx context.Context) ([]SelectNotRedeemedVtxosRow, error) {
	rows, err := q.db.QueryContext(ctx, selectNotRedeemedVtxos)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []SelectNotRedeemedVtxosRow
	for rows.Next() {
		var i SelectNotRedeemedVtxosRow
		if err := rows.Scan(
			&i.Vtxo.Txid,
			&i.Vtxo.Vout,
			&i.Vtxo.Amount,
			&i.Vtxo.PoolTx,
			&i.Vtxo.SpentBy,
			&i.Vtxo.Spent,
			&i.Vtxo.Redeemed,
			&i.Vtxo.Swept,
			&i.Vtxo.ExpireAt,
			&i.Vtxo.PaymentID,
			&i.Vtxo.RedeemTx,
			&i.Vtxo.Descriptor,
			&i.Vtxo.PendingChange,
			&i.UncondForfeitTxVw.ID,
			&i.UncondForfeitTxVw.Tx,
			&i.UncondForfeitTxVw.VtxoTxid,
			&i.UncondForfeitTxVw.VtxoVout,
			&i.UncondForfeitTxVw.Position,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const selectNotRedeemedVtxosWithPubkey = `-- name: SelectNotRedeemedVtxosWithPubkey :many
SELECT  vtxo.txid, vtxo.vout, vtxo.amount, vtxo.pool_tx, vtxo.spent_by, vtxo.spent, vtxo.redeemed, vtxo.swept, vtxo.expire_at, vtxo.payment_id, vtxo.redeem_tx, vtxo.descriptor, vtxo.pending_change,
        uncond_forfeit_tx_vw.id, uncond_forfeit_tx_vw.tx, uncond_forfeit_tx_vw.vtxo_txid, uncond_forfeit_tx_vw.vtxo_vout, uncond_forfeit_tx_vw.position
FROM vtxo
        LEFT OUTER JOIN uncond_forfeit_tx_vw ON vtxo.txid=uncond_forfeit_tx_vw.vtxo_txid AND vtxo.vout=uncond_forfeit_tx_vw.vtxo_vout
WHERE redeemed = false AND INSTR(descriptor, ?) > 0
`

type SelectNotRedeemedVtxosWithPubkeyRow struct {
	Vtxo              Vtxo
	UncondForfeitTxVw UncondForfeitTxVw
}

func (q *Queries) SelectNotRedeemedVtxosWithPubkey(ctx context.Context, instr string) ([]SelectNotRedeemedVtxosWithPubkeyRow, error) {
	rows, err := q.db.QueryContext(ctx, selectNotRedeemedVtxosWithPubkey, instr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []SelectNotRedeemedVtxosWithPubkeyRow
	for rows.Next() {
		var i SelectNotRedeemedVtxosWithPubkeyRow
		if err := rows.Scan(
			&i.Vtxo.Txid,
			&i.Vtxo.Vout,
			&i.Vtxo.Amount,
			&i.Vtxo.PoolTx,
			&i.Vtxo.SpentBy,
			&i.Vtxo.Spent,
			&i.Vtxo.Redeemed,
			&i.Vtxo.Swept,
			&i.Vtxo.ExpireAt,
			&i.Vtxo.PaymentID,
			&i.Vtxo.RedeemTx,
			&i.Vtxo.Descriptor,
			&i.Vtxo.PendingChange,
			&i.UncondForfeitTxVw.ID,
			&i.UncondForfeitTxVw.Tx,
			&i.UncondForfeitTxVw.VtxoTxid,
			&i.UncondForfeitTxVw.VtxoVout,
			&i.UncondForfeitTxVw.Position,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const selectRoundIds = `-- name: SelectRoundIds :many
SELECT id FROM round
`

func (q *Queries) SelectRoundIds(ctx context.Context) ([]string, error) {
	rows, err := q.db.QueryContext(ctx, selectRoundIds)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		items = append(items, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const selectRoundIdsInRange = `-- name: SelectRoundIdsInRange :many
SELECT id FROM round WHERE starting_timestamp > ? AND starting_timestamp < ?
`

type SelectRoundIdsInRangeParams struct {
	StartingTimestamp   int64
	StartingTimestamp_2 int64
}

func (q *Queries) SelectRoundIdsInRange(ctx context.Context, arg SelectRoundIdsInRangeParams) ([]string, error) {
	rows, err := q.db.QueryContext(ctx, selectRoundIdsInRange, arg.StartingTimestamp, arg.StartingTimestamp_2)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		items = append(items, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const selectRoundWithRoundId = `-- name: SelectRoundWithRoundId :many
SELECT round.id, round.starting_timestamp, round.ending_timestamp, round.ended, round.failed, round.stage_code, round.txid, round.unsigned_tx, round.connector_address, round.dust_amount, round.version, round.swept,
       round_payment_vw.id, round_payment_vw.round_id,
       round_tx_vw.id, round_tx_vw.tx, round_tx_vw.round_id, round_tx_vw.type, round_tx_vw.position, round_tx_vw.txid, round_tx_vw.tree_level, round_tx_vw.parent_txid, round_tx_vw.is_leaf,
       payment_receiver_vw.payment_id, payment_receiver_vw.descriptor, payment_receiver_vw.amount, payment_receiver_vw.onchain_address,
       payment_vtxo_vw.txid, payment_vtxo_vw.vout, payment_vtxo_vw.amount, payment_vtxo_vw.pool_tx, payment_vtxo_vw.spent_by, payment_vtxo_vw.spent, payment_vtxo_vw.redeemed, payment_vtxo_vw.swept, payment_vtxo_vw.expire_at, payment_vtxo_vw.payment_id, payment_vtxo_vw.redeem_tx, payment_vtxo_vw.descriptor, payment_vtxo_vw.pending_change
FROM round
         LEFT OUTER JOIN round_payment_vw ON round.id=round_payment_vw.round_id
         LEFT OUTER JOIN round_tx_vw ON round.id=round_tx_vw.round_id
         LEFT OUTER JOIN payment_receiver_vw ON round_payment_vw.id=payment_receiver_vw.payment_id
         LEFT OUTER JOIN payment_vtxo_vw ON round_payment_vw.id=payment_vtxo_vw.payment_id
WHERE round.id = ?
`

type SelectRoundWithRoundIdRow struct {
	Round             Round
	RoundPaymentVw    RoundPaymentVw
	RoundTxVw         RoundTxVw
	PaymentReceiverVw PaymentReceiverVw
	PaymentVtxoVw     PaymentVtxoVw
}

func (q *Queries) SelectRoundWithRoundId(ctx context.Context, id string) ([]SelectRoundWithRoundIdRow, error) {
	rows, err := q.db.QueryContext(ctx, selectRoundWithRoundId, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []SelectRoundWithRoundIdRow
	for rows.Next() {
		var i SelectRoundWithRoundIdRow
		if err := rows.Scan(
			&i.Round.ID,
			&i.Round.StartingTimestamp,
			&i.Round.EndingTimestamp,
			&i.Round.Ended,
			&i.Round.Failed,
			&i.Round.StageCode,
			&i.Round.Txid,
			&i.Round.UnsignedTx,
			&i.Round.ConnectorAddress,
			&i.Round.DustAmount,
			&i.Round.Version,
			&i.Round.Swept,
			&i.RoundPaymentVw.ID,
			&i.RoundPaymentVw.RoundID,
			&i.RoundTxVw.ID,
			&i.RoundTxVw.Tx,
			&i.RoundTxVw.RoundID,
			&i.RoundTxVw.Type,
			&i.RoundTxVw.Position,
			&i.RoundTxVw.Txid,
			&i.RoundTxVw.TreeLevel,
			&i.RoundTxVw.ParentTxid,
			&i.RoundTxVw.IsLeaf,
			&i.PaymentReceiverVw.PaymentID,
			&i.PaymentReceiverVw.Descriptor,
			&i.PaymentReceiverVw.Amount,
			&i.PaymentReceiverVw.OnchainAddress,
			&i.PaymentVtxoVw.Txid,
			&i.PaymentVtxoVw.Vout,
			&i.PaymentVtxoVw.Amount,
			&i.PaymentVtxoVw.PoolTx,
			&i.PaymentVtxoVw.SpentBy,
			&i.PaymentVtxoVw.Spent,
			&i.PaymentVtxoVw.Redeemed,
			&i.PaymentVtxoVw.Swept,
			&i.PaymentVtxoVw.ExpireAt,
			&i.PaymentVtxoVw.PaymentID,
			&i.PaymentVtxoVw.RedeemTx,
			&i.PaymentVtxoVw.Descriptor,
			&i.PaymentVtxoVw.PendingChange,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const selectRoundWithRoundTxId = `-- name: SelectRoundWithRoundTxId :many
SELECT round.id, round.starting_timestamp, round.ending_timestamp, round.ended, round.failed, round.stage_code, round.txid, round.unsigned_tx, round.connector_address, round.dust_amount, round.version, round.swept,
       round_payment_vw.id, round_payment_vw.round_id,
       round_tx_vw.id, round_tx_vw.tx, round_tx_vw.round_id, round_tx_vw.type, round_tx_vw.position, round_tx_vw.txid, round_tx_vw.tree_level, round_tx_vw.parent_txid, round_tx_vw.is_leaf,
       payment_receiver_vw.payment_id, payment_receiver_vw.descriptor, payment_receiver_vw.amount, payment_receiver_vw.onchain_address,
       payment_vtxo_vw.txid, payment_vtxo_vw.vout, payment_vtxo_vw.amount, payment_vtxo_vw.pool_tx, payment_vtxo_vw.spent_by, payment_vtxo_vw.spent, payment_vtxo_vw.redeemed, payment_vtxo_vw.swept, payment_vtxo_vw.expire_at, payment_vtxo_vw.payment_id, payment_vtxo_vw.redeem_tx, payment_vtxo_vw.descriptor, payment_vtxo_vw.pending_change
FROM round
         LEFT OUTER JOIN round_payment_vw ON round.id=round_payment_vw.round_id
         LEFT OUTER JOIN round_tx_vw ON round.id=round_tx_vw.round_id
         LEFT OUTER JOIN payment_receiver_vw ON round_payment_vw.id=payment_receiver_vw.payment_id
         LEFT OUTER JOIN payment_vtxo_vw ON round_payment_vw.id=payment_vtxo_vw.payment_id
WHERE round.txid = ?
`

type SelectRoundWithRoundTxIdRow struct {
	Round             Round
	RoundPaymentVw    RoundPaymentVw
	RoundTxVw         RoundTxVw
	PaymentReceiverVw PaymentReceiverVw
	PaymentVtxoVw     PaymentVtxoVw
}

func (q *Queries) SelectRoundWithRoundTxId(ctx context.Context, txid string) ([]SelectRoundWithRoundTxIdRow, error) {
	rows, err := q.db.QueryContext(ctx, selectRoundWithRoundTxId, txid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []SelectRoundWithRoundTxIdRow
	for rows.Next() {
		var i SelectRoundWithRoundTxIdRow
		if err := rows.Scan(
			&i.Round.ID,
			&i.Round.StartingTimestamp,
			&i.Round.EndingTimestamp,
			&i.Round.Ended,
			&i.Round.Failed,
			&i.Round.StageCode,
			&i.Round.Txid,
			&i.Round.UnsignedTx,
			&i.Round.ConnectorAddress,
			&i.Round.DustAmount,
			&i.Round.Version,
			&i.Round.Swept,
			&i.RoundPaymentVw.ID,
			&i.RoundPaymentVw.RoundID,
			&i.RoundTxVw.ID,
			&i.RoundTxVw.Tx,
			&i.RoundTxVw.RoundID,
			&i.RoundTxVw.Type,
			&i.RoundTxVw.Position,
			&i.RoundTxVw.Txid,
			&i.RoundTxVw.TreeLevel,
			&i.RoundTxVw.ParentTxid,
			&i.RoundTxVw.IsLeaf,
			&i.PaymentReceiverVw.PaymentID,
			&i.PaymentReceiverVw.Descriptor,
			&i.PaymentReceiverVw.Amount,
			&i.PaymentReceiverVw.OnchainAddress,
			&i.PaymentVtxoVw.Txid,
			&i.PaymentVtxoVw.Vout,
			&i.PaymentVtxoVw.Amount,
			&i.PaymentVtxoVw.PoolTx,
			&i.PaymentVtxoVw.SpentBy,
			&i.PaymentVtxoVw.Spent,
			&i.PaymentVtxoVw.Redeemed,
			&i.PaymentVtxoVw.Swept,
			&i.PaymentVtxoVw.ExpireAt,
			&i.PaymentVtxoVw.PaymentID,
			&i.PaymentVtxoVw.RedeemTx,
			&i.PaymentVtxoVw.Descriptor,
			&i.PaymentVtxoVw.PendingChange,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const selectSweepableRounds = `-- name: SelectSweepableRounds :many
SELECT round.id, round.starting_timestamp, round.ending_timestamp, round.ended, round.failed, round.stage_code, round.txid, round.unsigned_tx, round.connector_address, round.dust_amount, round.version, round.swept,
       round_payment_vw.id, round_payment_vw.round_id,
       round_tx_vw.id, round_tx_vw.tx, round_tx_vw.round_id, round_tx_vw.type, round_tx_vw.position, round_tx_vw.txid, round_tx_vw.tree_level, round_tx_vw.parent_txid, round_tx_vw.is_leaf,
       payment_receiver_vw.payment_id, payment_receiver_vw.descriptor, payment_receiver_vw.amount, payment_receiver_vw.onchain_address,
       payment_vtxo_vw.txid, payment_vtxo_vw.vout, payment_vtxo_vw.amount, payment_vtxo_vw.pool_tx, payment_vtxo_vw.spent_by, payment_vtxo_vw.spent, payment_vtxo_vw.redeemed, payment_vtxo_vw.swept, payment_vtxo_vw.expire_at, payment_vtxo_vw.payment_id, payment_vtxo_vw.redeem_tx, payment_vtxo_vw.descriptor, payment_vtxo_vw.pending_change
FROM round
         LEFT OUTER JOIN round_payment_vw ON round.id=round_payment_vw.round_id
         LEFT OUTER JOIN round_tx_vw ON round.id=round_tx_vw.round_id
         LEFT OUTER JOIN payment_receiver_vw ON round_payment_vw.id=payment_receiver_vw.payment_id
         LEFT OUTER JOIN payment_vtxo_vw ON round_payment_vw.id=payment_vtxo_vw.payment_id
WHERE round.swept = false AND round.ended = true AND round.failed = false
`

type SelectSweepableRoundsRow struct {
	Round             Round
	RoundPaymentVw    RoundPaymentVw
	RoundTxVw         RoundTxVw
	PaymentReceiverVw PaymentReceiverVw
	PaymentVtxoVw     PaymentVtxoVw
}

func (q *Queries) SelectSweepableRounds(ctx context.Context) ([]SelectSweepableRoundsRow, error) {
	rows, err := q.db.QueryContext(ctx, selectSweepableRounds)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []SelectSweepableRoundsRow
	for rows.Next() {
		var i SelectSweepableRoundsRow
		if err := rows.Scan(
			&i.Round.ID,
			&i.Round.StartingTimestamp,
			&i.Round.EndingTimestamp,
			&i.Round.Ended,
			&i.Round.Failed,
			&i.Round.StageCode,
			&i.Round.Txid,
			&i.Round.UnsignedTx,
			&i.Round.ConnectorAddress,
			&i.Round.DustAmount,
			&i.Round.Version,
			&i.Round.Swept,
			&i.RoundPaymentVw.ID,
			&i.RoundPaymentVw.RoundID,
			&i.RoundTxVw.ID,
			&i.RoundTxVw.Tx,
			&i.RoundTxVw.RoundID,
			&i.RoundTxVw.Type,
			&i.RoundTxVw.Position,
			&i.RoundTxVw.Txid,
			&i.RoundTxVw.TreeLevel,
			&i.RoundTxVw.ParentTxid,
			&i.RoundTxVw.IsLeaf,
			&i.PaymentReceiverVw.PaymentID,
			&i.PaymentReceiverVw.Descriptor,
			&i.PaymentReceiverVw.Amount,
			&i.PaymentReceiverVw.OnchainAddress,
			&i.PaymentVtxoVw.Txid,
			&i.PaymentVtxoVw.Vout,
			&i.PaymentVtxoVw.Amount,
			&i.PaymentVtxoVw.PoolTx,
			&i.PaymentVtxoVw.SpentBy,
			&i.PaymentVtxoVw.Spent,
			&i.PaymentVtxoVw.Redeemed,
			&i.PaymentVtxoVw.Swept,
			&i.PaymentVtxoVw.ExpireAt,
			&i.PaymentVtxoVw.PaymentID,
			&i.PaymentVtxoVw.RedeemTx,
			&i.PaymentVtxoVw.Descriptor,
			&i.PaymentVtxoVw.PendingChange,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const selectSweepableVtxos = `-- name: SelectSweepableVtxos :many
SELECT  vtxo.txid, vtxo.vout, vtxo.amount, vtxo.pool_tx, vtxo.spent_by, vtxo.spent, vtxo.redeemed, vtxo.swept, vtxo.expire_at, vtxo.payment_id, vtxo.redeem_tx, vtxo.descriptor, vtxo.pending_change,
        uncond_forfeit_tx_vw.id, uncond_forfeit_tx_vw.tx, uncond_forfeit_tx_vw.vtxo_txid, uncond_forfeit_tx_vw.vtxo_vout, uncond_forfeit_tx_vw.position
FROM vtxo
        LEFT OUTER JOIN uncond_forfeit_tx_vw ON vtxo.txid=uncond_forfeit_tx_vw.vtxo_txid AND vtxo.vout=uncond_forfeit_tx_vw.vtxo_vout
WHERE redeemed = false AND swept = false
`

type SelectSweepableVtxosRow struct {
	Vtxo              Vtxo
	UncondForfeitTxVw UncondForfeitTxVw
}

func (q *Queries) SelectSweepableVtxos(ctx context.Context) ([]SelectSweepableVtxosRow, error) {
	rows, err := q.db.QueryContext(ctx, selectSweepableVtxos)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []SelectSweepableVtxosRow
	for rows.Next() {
		var i SelectSweepableVtxosRow
		if err := rows.Scan(
			&i.Vtxo.Txid,
			&i.Vtxo.Vout,
			&i.Vtxo.Amount,
			&i.Vtxo.PoolTx,
			&i.Vtxo.SpentBy,
			&i.Vtxo.Spent,
			&i.Vtxo.Redeemed,
			&i.Vtxo.Swept,
			&i.Vtxo.ExpireAt,
			&i.Vtxo.PaymentID,
			&i.Vtxo.RedeemTx,
			&i.Vtxo.Descriptor,
			&i.Vtxo.PendingChange,
			&i.UncondForfeitTxVw.ID,
			&i.UncondForfeitTxVw.Tx,
			&i.UncondForfeitTxVw.VtxoTxid,
			&i.UncondForfeitTxVw.VtxoVout,
			&i.UncondForfeitTxVw.Position,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const selectSweptRounds = `-- name: SelectSweptRounds :many
SELECT round.id, round.starting_timestamp, round.ending_timestamp, round.ended, round.failed, round.stage_code, round.txid, round.unsigned_tx, round.connector_address, round.dust_amount, round.version, round.swept,
       round_payment_vw.id, round_payment_vw.round_id,
       round_tx_vw.id, round_tx_vw.tx, round_tx_vw.round_id, round_tx_vw.type, round_tx_vw.position, round_tx_vw.txid, round_tx_vw.tree_level, round_tx_vw.parent_txid, round_tx_vw.is_leaf,
       payment_receiver_vw.payment_id, payment_receiver_vw.descriptor, payment_receiver_vw.amount, payment_receiver_vw.onchain_address,
       payment_vtxo_vw.txid, payment_vtxo_vw.vout, payment_vtxo_vw.amount, payment_vtxo_vw.pool_tx, payment_vtxo_vw.spent_by, payment_vtxo_vw.spent, payment_vtxo_vw.redeemed, payment_vtxo_vw.swept, payment_vtxo_vw.expire_at, payment_vtxo_vw.payment_id, payment_vtxo_vw.redeem_tx, payment_vtxo_vw.descriptor, payment_vtxo_vw.pending_change
FROM round
         LEFT OUTER JOIN round_payment_vw ON round.id=round_payment_vw.round_id
         LEFT OUTER JOIN round_tx_vw ON round.id=round_tx_vw.round_id
         LEFT OUTER JOIN payment_receiver_vw ON round_payment_vw.id=payment_receiver_vw.payment_id
         LEFT OUTER JOIN payment_vtxo_vw ON round_payment_vw.id=payment_vtxo_vw.payment_id
WHERE round.swept = true AND round.failed = false AND round.ended = true AND round.connector_address <> ''
`

type SelectSweptRoundsRow struct {
	Round             Round
	RoundPaymentVw    RoundPaymentVw
	RoundTxVw         RoundTxVw
	PaymentReceiverVw PaymentReceiverVw
	PaymentVtxoVw     PaymentVtxoVw
}

func (q *Queries) SelectSweptRounds(ctx context.Context) ([]SelectSweptRoundsRow, error) {
	rows, err := q.db.QueryContext(ctx, selectSweptRounds)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []SelectSweptRoundsRow
	for rows.Next() {
		var i SelectSweptRoundsRow
		if err := rows.Scan(
			&i.Round.ID,
			&i.Round.StartingTimestamp,
			&i.Round.EndingTimestamp,
			&i.Round.Ended,
			&i.Round.Failed,
			&i.Round.StageCode,
			&i.Round.Txid,
			&i.Round.UnsignedTx,
			&i.Round.ConnectorAddress,
			&i.Round.DustAmount,
			&i.Round.Version,
			&i.Round.Swept,
			&i.RoundPaymentVw.ID,
			&i.RoundPaymentVw.RoundID,
			&i.RoundTxVw.ID,
			&i.RoundTxVw.Tx,
			&i.RoundTxVw.RoundID,
			&i.RoundTxVw.Type,
			&i.RoundTxVw.Position,
			&i.RoundTxVw.Txid,
			&i.RoundTxVw.TreeLevel,
			&i.RoundTxVw.ParentTxid,
			&i.RoundTxVw.IsLeaf,
			&i.PaymentReceiverVw.PaymentID,
			&i.PaymentReceiverVw.Descriptor,
			&i.PaymentReceiverVw.Amount,
			&i.PaymentReceiverVw.OnchainAddress,
			&i.PaymentVtxoVw.Txid,
			&i.PaymentVtxoVw.Vout,
			&i.PaymentVtxoVw.Amount,
			&i.PaymentVtxoVw.PoolTx,
			&i.PaymentVtxoVw.SpentBy,
			&i.PaymentVtxoVw.Spent,
			&i.PaymentVtxoVw.Redeemed,
			&i.PaymentVtxoVw.Swept,
			&i.PaymentVtxoVw.ExpireAt,
			&i.PaymentVtxoVw.PaymentID,
			&i.PaymentVtxoVw.RedeemTx,
			&i.PaymentVtxoVw.Descriptor,
			&i.PaymentVtxoVw.PendingChange,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const selectVtxoByOutpoint = `-- name: SelectVtxoByOutpoint :one
SELECT  vtxo.txid, vtxo.vout, vtxo.amount, vtxo.pool_tx, vtxo.spent_by, vtxo.spent, vtxo.redeemed, vtxo.swept, vtxo.expire_at, vtxo.payment_id, vtxo.redeem_tx, vtxo.descriptor, vtxo.pending_change,
        uncond_forfeit_tx_vw.id, uncond_forfeit_tx_vw.tx, uncond_forfeit_tx_vw.vtxo_txid, uncond_forfeit_tx_vw.vtxo_vout, uncond_forfeit_tx_vw.position
FROM vtxo
        LEFT OUTER JOIN uncond_forfeit_tx_vw ON vtxo.txid=uncond_forfeit_tx_vw.vtxo_txid AND vtxo.vout=uncond_forfeit_tx_vw.vtxo_vout
WHERE txid = ? AND vout = ?
`

type SelectVtxoByOutpointParams struct {
	Txid string
	Vout int64
}

type SelectVtxoByOutpointRow struct {
	Vtxo              Vtxo
	UncondForfeitTxVw UncondForfeitTxVw
}

func (q *Queries) SelectVtxoByOutpoint(ctx context.Context, arg SelectVtxoByOutpointParams) (SelectVtxoByOutpointRow, error) {
	row := q.db.QueryRowContext(ctx, selectVtxoByOutpoint, arg.Txid, arg.Vout)
	var i SelectVtxoByOutpointRow
	err := row.Scan(
		&i.Vtxo.Txid,
		&i.Vtxo.Vout,
		&i.Vtxo.Amount,
		&i.Vtxo.PoolTx,
		&i.Vtxo.SpentBy,
		&i.Vtxo.Spent,
		&i.Vtxo.Redeemed,
		&i.Vtxo.Swept,
		&i.Vtxo.ExpireAt,
		&i.Vtxo.PaymentID,
		&i.Vtxo.RedeemTx,
		&i.Vtxo.Descriptor,
		&i.Vtxo.PendingChange,
		&i.UncondForfeitTxVw.ID,
		&i.UncondForfeitTxVw.Tx,
		&i.UncondForfeitTxVw.VtxoTxid,
		&i.UncondForfeitTxVw.VtxoVout,
		&i.UncondForfeitTxVw.Position,
	)
	return i, err
}

const selectVtxosByPoolTxid = `-- name: SelectVtxosByPoolTxid :many
SELECT  vtxo.txid, vtxo.vout, vtxo.amount, vtxo.pool_tx, vtxo.spent_by, vtxo.spent, vtxo.redeemed, vtxo.swept, vtxo.expire_at, vtxo.payment_id, vtxo.redeem_tx, vtxo.descriptor, vtxo.pending_change,
        uncond_forfeit_tx_vw.id, uncond_forfeit_tx_vw.tx, uncond_forfeit_tx_vw.vtxo_txid, uncond_forfeit_tx_vw.vtxo_vout, uncond_forfeit_tx_vw.position
FROM vtxo
        LEFT OUTER JOIN uncond_forfeit_tx_vw ON vtxo.txid=uncond_forfeit_tx_vw.vtxo_txid AND vtxo.vout=uncond_forfeit_tx_vw.vtxo_vout
WHERE pool_tx = ?
`

type SelectVtxosByPoolTxidRow struct {
	Vtxo              Vtxo
	UncondForfeitTxVw UncondForfeitTxVw
}

func (q *Queries) SelectVtxosByPoolTxid(ctx context.Context, poolTx string) ([]SelectVtxosByPoolTxidRow, error) {
	rows, err := q.db.QueryContext(ctx, selectVtxosByPoolTxid, poolTx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []SelectVtxosByPoolTxidRow
	for rows.Next() {
		var i SelectVtxosByPoolTxidRow
		if err := rows.Scan(
			&i.Vtxo.Txid,
			&i.Vtxo.Vout,
			&i.Vtxo.Amount,
			&i.Vtxo.PoolTx,
			&i.Vtxo.SpentBy,
			&i.Vtxo.Spent,
			&i.Vtxo.Redeemed,
			&i.Vtxo.Swept,
			&i.Vtxo.ExpireAt,
			&i.Vtxo.PaymentID,
			&i.Vtxo.RedeemTx,
			&i.Vtxo.Descriptor,
			&i.Vtxo.PendingChange,
			&i.UncondForfeitTxVw.ID,
			&i.UncondForfeitTxVw.Tx,
			&i.UncondForfeitTxVw.VtxoTxid,
			&i.UncondForfeitTxVw.VtxoVout,
			&i.UncondForfeitTxVw.Position,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateVtxoExpireAt = `-- name: UpdateVtxoExpireAt :exec
UPDATE vtxo SET expire_at = ? WHERE txid = ? AND vout = ?
`

type UpdateVtxoExpireAtParams struct {
	ExpireAt int64
	Txid     string
	Vout     int64
}

func (q *Queries) UpdateVtxoExpireAt(ctx context.Context, arg UpdateVtxoExpireAtParams) error {
	_, err := q.db.ExecContext(ctx, updateVtxoExpireAt, arg.ExpireAt, arg.Txid, arg.Vout)
	return err
}

const updateVtxoPaymentId = `-- name: UpdateVtxoPaymentId :exec
UPDATE vtxo SET payment_id = ? WHERE txid = ? AND vout = ?
`

type UpdateVtxoPaymentIdParams struct {
	PaymentID sql.NullString
	Txid      string
	Vout      int64
}

func (q *Queries) UpdateVtxoPaymentId(ctx context.Context, arg UpdateVtxoPaymentIdParams) error {
	_, err := q.db.ExecContext(ctx, updateVtxoPaymentId, arg.PaymentID, arg.Txid, arg.Vout)
	return err
}

const upsertPayment = `-- name: UpsertPayment :exec
INSERT INTO payment (id, round_id) VALUES (?, ?)
ON CONFLICT(id) DO UPDATE SET round_id = EXCLUDED.round_id
`

type UpsertPaymentParams struct {
	ID      string
	RoundID string
}

func (q *Queries) UpsertPayment(ctx context.Context, arg UpsertPaymentParams) error {
	_, err := q.db.ExecContext(ctx, upsertPayment, arg.ID, arg.RoundID)
	return err
}

const upsertReceiver = `-- name: UpsertReceiver :exec
INSERT INTO receiver (payment_id, descriptor, amount, onchain_address) VALUES (?, ?, ?, ?)
ON CONFLICT(payment_id, descriptor) DO UPDATE SET
    amount = EXCLUDED.amount,
    onchain_address = EXCLUDED.onchain_address,
    descriptor = EXCLUDED.descriptor
`

type UpsertReceiverParams struct {
	PaymentID      string
	Descriptor     string
	Amount         int64
	OnchainAddress string
}

func (q *Queries) UpsertReceiver(ctx context.Context, arg UpsertReceiverParams) error {
	_, err := q.db.ExecContext(ctx, upsertReceiver,
		arg.PaymentID,
		arg.Descriptor,
		arg.Amount,
		arg.OnchainAddress,
	)
	return err
}

const upsertRound = `-- name: UpsertRound :exec
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
    swept = EXCLUDED.swept
`

type UpsertRoundParams struct {
	ID                string
	StartingTimestamp int64
	EndingTimestamp   int64
	Ended             bool
	Failed            bool
	StageCode         int64
	Txid              string
	UnsignedTx        string
	ConnectorAddress  string
	DustAmount        int64
	Version           int64
	Swept             bool
}

func (q *Queries) UpsertRound(ctx context.Context, arg UpsertRoundParams) error {
	_, err := q.db.ExecContext(ctx, upsertRound,
		arg.ID,
		arg.StartingTimestamp,
		arg.EndingTimestamp,
		arg.Ended,
		arg.Failed,
		arg.StageCode,
		arg.Txid,
		arg.UnsignedTx,
		arg.ConnectorAddress,
		arg.DustAmount,
		arg.Version,
		arg.Swept,
	)
	return err
}

const upsertTransaction = `-- name: UpsertTransaction :exec
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
    is_leaf = EXCLUDED.is_leaf
`

type UpsertTransactionParams struct {
	Tx         string
	RoundID    string
	Type       string
	Position   int64
	Txid       sql.NullString
	TreeLevel  sql.NullInt64
	ParentTxid sql.NullString
	IsLeaf     sql.NullBool
}

func (q *Queries) UpsertTransaction(ctx context.Context, arg UpsertTransactionParams) error {
	_, err := q.db.ExecContext(ctx, upsertTransaction,
		arg.Tx,
		arg.RoundID,
		arg.Type,
		arg.Position,
		arg.Txid,
		arg.TreeLevel,
		arg.ParentTxid,
		arg.IsLeaf,
	)
	return err
}

const upsertUnconditionalForfeitTx = `-- name: UpsertUnconditionalForfeitTx :exec
INSERT INTO uncond_forfeit_tx (tx, vtxo_txid, vtxo_vout, position)
VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET
    tx = EXCLUDED.tx,
    vtxo_txid = EXCLUDED.vtxo_txid,
    vtxo_vout = EXCLUDED.vtxo_vout,
    position = EXCLUDED.position
`

type UpsertUnconditionalForfeitTxParams struct {
	Tx       string
	VtxoTxid string
	VtxoVout int64
	Position int64
}

func (q *Queries) UpsertUnconditionalForfeitTx(ctx context.Context, arg UpsertUnconditionalForfeitTxParams) error {
	_, err := q.db.ExecContext(ctx, upsertUnconditionalForfeitTx,
		arg.Tx,
		arg.VtxoTxid,
		arg.VtxoVout,
		arg.Position,
	)
	return err
}

const upsertVtxo = `-- name: UpsertVtxo :exec
INSERT INTO vtxo (txid, vout, descriptor, amount, pool_tx, spent_by, spent, redeemed, swept, expire_at, redeem_tx, pending_change)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(txid, vout) DO UPDATE SET
    descriptor = EXCLUDED.descriptor,
    amount = EXCLUDED.amount,
    pool_tx = EXCLUDED.pool_tx,
    spent_by = EXCLUDED.spent_by,
    spent = EXCLUDED.spent,
    redeemed = EXCLUDED.redeemed,
    swept = EXCLUDED.swept,
    expire_at = EXCLUDED.expire_at,
    redeem_tx = EXCLUDED.redeem_tx,
    pending_change = EXCLUDED.pending_change
`

type UpsertVtxoParams struct {
	Txid          string
	Vout          int64
	Descriptor    sql.NullString
	Amount        int64
	PoolTx        string
	SpentBy       string
	Spent         bool
	Redeemed      bool
	Swept         bool
	ExpireAt      int64
	RedeemTx      sql.NullString
	PendingChange sql.NullBool
}

func (q *Queries) UpsertVtxo(ctx context.Context, arg UpsertVtxoParams) error {
	_, err := q.db.ExecContext(ctx, upsertVtxo,
		arg.Txid,
		arg.Vout,
		arg.Descriptor,
		arg.Amount,
		arg.PoolTx,
		arg.SpentBy,
		arg.Spent,
		arg.Redeemed,
		arg.Swept,
		arg.ExpireAt,
		arg.RedeemTx,
		arg.PendingChange,
	)
	return err
}
