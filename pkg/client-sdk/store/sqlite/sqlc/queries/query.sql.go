// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: query.sql

package queries

import (
	"context"
)

const selectAllTransactions = `-- name: SelectAllTransactions :many
SELECT id, boarding_txid, round_txid, redeem_txid, amount, type, pending, claimed, created_at FROM txs
`

// Transaction
func (q *Queries) SelectAllTransactions(ctx context.Context) ([]Tx, error) {
	rows, err := q.db.QueryContext(ctx, selectAllTransactions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Tx
	for rows.Next() {
		var i Tx
		if err := rows.Scan(
			&i.ID,
			&i.BoardingTxid,
			&i.RoundTxid,
			&i.RedeemTxid,
			&i.Amount,
			&i.Type,
			&i.Pending,
			&i.Claimed,
			&i.CreatedAt,
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

const selectAllVtxos = `-- name: SelectAllVtxos :many

SELECT txid, vout, amount, round_txid, expires_at, redeem_tx, unconditional_forfeit_txs, pending, spent_by, spent FROM vtxo
`

// Vtxo
func (q *Queries) SelectAllVtxos(ctx context.Context) ([]Vtxo, error) {
	rows, err := q.db.QueryContext(ctx, selectAllVtxos)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Vtxo
	for rows.Next() {
		var i Vtxo
		if err := rows.Scan(
			&i.Txid,
			&i.Vout,
			&i.Amount,
			&i.RoundTxid,
			&i.ExpiresAt,
			&i.RedeemTx,
			&i.UnconditionalForfeitTxs,
			&i.Pending,
			&i.SpentBy,
			&i.Spent,
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

const selectBoardingTransaction = `-- name: SelectBoardingTransaction :many
SELECT id, boarding_txid, round_txid, redeem_txid, amount, type, pending, claimed, created_at FROM txs WHERE boarding_txid <> ''
`

func (q *Queries) SelectBoardingTransaction(ctx context.Context) ([]Tx, error) {
	rows, err := q.db.QueryContext(ctx, selectBoardingTransaction)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Tx
	for rows.Next() {
		var i Tx
		if err := rows.Scan(
			&i.ID,
			&i.BoardingTxid,
			&i.RoundTxid,
			&i.RedeemTxid,
			&i.Amount,
			&i.Type,
			&i.Pending,
			&i.Claimed,
			&i.CreatedAt,
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
