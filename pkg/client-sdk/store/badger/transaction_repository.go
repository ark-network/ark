package badgerstore

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/ark-network/ark/pkg/client-sdk/store/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/google/uuid"
	"github.com/timshannon/badgerhold/v4"
)

const (
	transactionStoreDir = "transactions"
)

type transactionRepository struct {
	db      *badgerhold.Store
	eventCh chan domain.Transaction
}

func NewTransactionRepository(
	dir string, logger badger.Logger,
) (domain.TransactionRepository, error) {
	badgerDb, err := CreateDB(filepath.Join(dir, transactionStoreDir), logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open round events store: %s", err)
	}
	return &transactionRepository{
		db:      badgerDb,
		eventCh: make(chan domain.Transaction),
	}, nil
}

func (t *transactionRepository) GetBoardingTxs(ctx context.Context) ([]domain.Transaction, error) {
	var txs []domain.Transaction
	query := badgerhold.Where("BoardingTxid").Ne("")
	err := t.db.Find(&txs, query)
	return txs, err
}

func (t *transactionRepository) InsertTransactions(ctx context.Context, txs []domain.Transaction) error {
	for _, tx := range txs {
		tx.ID = uuid.New().String()
		if err := t.db.Insert(tx.ID, &tx); err != nil {
			return err
		}
		go func(trx domain.Transaction) {
			t.eventCh <- trx
		}(tx)
	}
	return nil
}

func (t *transactionRepository) GetAll(ctx context.Context) ([]domain.Transaction, error) {
	var txs []domain.Transaction
	err := t.db.Find(&txs, nil)
	return txs, err
}

func (t *transactionRepository) GetEventChannel() chan domain.Transaction {
	return t.eventCh
}

func (t *transactionRepository) Stop() {
	close(t.eventCh)
}
