package sqlitestore

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/store/sqlite/sqlc/queries"
)

type vtxoRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewVtxoRepository(db *sql.DB) store.VtxoRepository {
	return &vtxoRepository{
		db:      db,
		querier: queries.New(db),
	}
}

func (v *vtxoRepository) GetAll(
	ctx context.Context,
) (spendable []store.Vtxo, spent []store.Vtxo, err error) {
	rows, err := v.querier.SelectAllVtxos(ctx)
	if err != nil {
		return nil, nil, err
	}

	spendableVtxos := make([]store.Vtxo, 0)
	spentVxos := make([]store.Vtxo, 0)
	for _, v := range rows {
		roundTxID := ""
		if v.RoundTxid.Valid {
			roundTxID = v.RoundTxid.String
		}

		redeemTx := ""
		if v.RedeemTx.Valid {
			redeemTx = v.RedeemTx.String
		}

		unconditionalForfeitTxs := make([]string, 0)
		if v.UnconditionalForfeitTxs.Valid {
			unconditionalForfeitTxs = strings.Split(v.UnconditionalForfeitTxs.String, ",")
		}

		pending := false
		if v.Pending.Valid {
			pending = v.Pending.Bool
		}

		spentBy := ""
		if v.SpentBy.Valid {
			spentBy = v.SpentBy.String
		}

		spent := false
		if v.Spent.Valid {
			spent = v.Spent.Bool
		}

		expiresAt := time.Unix(v.ExpiresAt, 0)

		vtxo := store.Vtxo{
			Txid:                    v.Txid,
			VOut:                    uint32(v.Vout),
			Amount:                  uint64(v.Amount),
			RoundTxid:               roundTxID,
			ExpiresAt:               &expiresAt,
			RedeemTx:                redeemTx,
			UnconditionalForfeitTxs: unconditionalForfeitTxs,
			Pending:                 pending,
			SpentBy:                 spentBy,
			Spent:                   spent,
		}
		if spent {
			spentVxos = append(spentVxos, vtxo)
		} else {
			spendableVtxos = append(spendableVtxos, vtxo)
		}

	}

	return spendableVtxos, spentVxos, nil
}

const insertVtxos = `
INSERT INTO vtxo (
			txid, vout, amount, round_txid, expires_at, redeem_tx, unconditional_forfeit_txs, pending, spent_by, spent
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

func (v *vtxoRepository) InsertVtxos(ctx context.Context, vtxos []store.Vtxo) error {
	// Start a transaction
	tx, err := v.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Prepare the statement
	stmt, err := tx.PrepareContext(ctx, insertVtxos)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, vtxo := range vtxos {
		var expiresAt sql.NullInt64
		if vtxo.ExpiresAt != nil {
			expiresAt = sql.NullInt64{Int64: vtxo.ExpiresAt.Unix(), Valid: true}
		}

		unconditionalForfeitTxs := ""
		if vtxo.UnconditionalForfeitTxs != nil {
			for _, tx := range vtxo.UnconditionalForfeitTxs {
				unconditionalForfeitTxs += tx + ","
			}
		}

		_, err := stmt.ExecContext(ctx,
			vtxo.Txid,
			vtxo.VOut,
			vtxo.Amount,
			vtxo.RoundTxid,
			expiresAt,
			vtxo.RedeemTx,
			unconditionalForfeitTxs,
			vtxo.Pending,
			vtxo.SpentBy,
			vtxo.Spent,
		)
		if err != nil {
			return err
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}
