package sqlitestore

import (
	"context"
	"database/sql"
	"time"

	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/store/sqlite/sqlc/queries"
	"github.com/google/uuid"
)

type transactionRepository struct {
	db      *sql.DB
	querier *queries.Queries

	eventChannel chan store.Transaction
}

func NewTransactionRepository(db *sql.DB) store.TransactionRepository {
	return &transactionRepository{
		db:           db,
		querier:      queries.New(db),
		eventChannel: make(chan store.Transaction),
	}
}

const insertTransaction = `
INSERT INTO txs (
    id,
    boarding_txid,
    round_txid,
    redeem_txid,
    amount,
    type,
    pending,
    claimed,
    created_at
) VALUES (
    ?,?, ?, ?, ?, ?, ?, ?, ?
)`

func (t *transactionRepository) InsertTransactions(ctx context.Context, txs []store.Transaction) error {
	dbTx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer dbTx.Rollback()

	// Prepare the statement
	stmt, err := dbTx.PrepareContext(ctx, insertTransaction)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, tx := range txs {
		_, err := stmt.ExecContext(ctx,
			uuid.New().String(),
			tx.BoardingTxid,
			tx.RoundTxid,
			tx.RedeemTxid,
			int64(tx.Amount),
			string(tx.Type),
			tx.IsPending,
			tx.CreatedAt.Unix(),
		)
		if err != nil {
			return err
		}

		go func(transaction store.Transaction) {
			t.eventChannel <- transaction
		}(tx)
	}

	if err := dbTx.Commit(); err != nil {
		return err
	}

	return nil
}

func (t *transactionRepository) GetAll(
	ctx context.Context,
) ([]store.Transaction, error) {
	rows, err := t.querier.SelectAllTransactions(ctx)
	if err != nil {
		return nil, err
	}

	resp := make([]store.Transaction, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, store.Transaction{
			ID:           row.ID,
			BoardingTxid: row.BoardingTxid,
			RoundTxid:    row.RoundTxid,
			RedeemTxid:   row.RedeemTxid,
			Amount:       uint64(row.Amount),
			Type:         store.TxType(row.Type),
			IsPending:    row.Pending,
			CreatedAt:    time.Unix(row.CreatedAt, 0),
		})
	}

	return resp, nil
}

func (t *transactionRepository) GetEventChannel() chan store.Transaction {
	return t.eventChannel
}

func (t *transactionRepository) Stop() {
	close(t.eventChannel)
}

func (t *transactionRepository) GetBoardingTxs(ctx context.Context) ([]store.Transaction, error) {
	rows, err := t.querier.SelectBoardingTransaction(ctx)
	if err != nil {
		return nil, err
	}

	resp := make([]store.Transaction, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, store.Transaction{
			ID:           row.ID,
			BoardingTxid: row.BoardingTxid,
			RoundTxid:    row.RoundTxid,
			RedeemTxid:   row.RedeemTxid,
			Amount:       uint64(row.Amount),
			Type:         store.TxType(row.Type),
			IsPending:    row.Pending,
			CreatedAt:    time.Unix(row.CreatedAt, 0),
		})
	}

	return resp, nil
}
