package badgerstore

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/ark-network/ark/pkg/client-sdk/store/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const (
	transactionStoreDir = "transactions"
)

type transactionRepository struct {
	db      *badgerhold.Store
	eventCh chan domain.TransactionEvent
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
		eventCh: make(chan domain.TransactionEvent),
	}, nil
}

func (t *transactionRepository) GetBoardingTxs(ctx context.Context) ([]domain.Transaction, error) {
	var txs []domain.Transaction
	query := badgerhold.Where("BoardingTxid").Ne("")
	err := t.db.Find(&txs, query)
	return txs, err
}

func (t *transactionRepository) InsertTransactions(
	ctx context.Context,
	txs []domain.Transaction,
) error {
	for _, tx := range txs {
		if err := t.db.Insert(tx.Key(), &tx); err != nil {
			return err
		}
		go func(trx domain.Transaction) {
			var eventType domain.EventType

			//covenantless transactions
			if trx.IsRedeem() {
				switch trx.Type {
				case domain.TxSent:
					eventType = domain.ArkSent
				case domain.TxReceived:
					eventType = domain.ArkReceivedPending
				}
			}

			if trx.IsRound() {
				switch trx.Type {
				case domain.TxSent:
					eventType = domain.ArkSentClaimed
				case domain.TxReceived:
					eventType = domain.ArkReceivedClaimed
				}
			}

			//TODO covenant transactions
			//if !trx.IsRedeem() && trx.IsRound() {
			//	if trx.Type == domain.TxSent {
			//		eventType = domain.ArkSent
			//	}
			//
			//	if trx.Type == domain.TxReceived {
			//		eventType = domain.ArkReceived
			//	}
			//}

			if trx.IsBoarding() {
				eventType = domain.BoardingPending
			}

			t.eventCh <- domain.TransactionEvent{
				Tx:    trx,
				Event: eventType,
			}
		}(tx)
	}
	return nil
}

func (t *transactionRepository) UpdateTransactions(
	ctx context.Context,
	txs []domain.Transaction,
) error {
	for _, tx := range txs {
		if err := t.db.Upsert(tx.Key(), &tx); err != nil {
			return err
		}
		go func(trx domain.Transaction) {
			var event domain.EventType

			// covenantless
			//if trx.IsRedeem() {
			//	if trx.Type == domain.TxSent && !trx.IsPending {
			//		event = domain.ArkSentClaimed
			//	}
			//
			//	if trx.Type == domain.TxReceived && !trx.IsPending {
			//		event = domain.ArkReceivedClaimed
			//	}
			//}

			//TODO covenant

			if trx.IsBoarding() {
				event = domain.BoardingClaimed
			}

			t.eventCh <- domain.TransactionEvent{
				Tx:    trx,
				Event: event,
			}
		}(tx)
	}
	return nil
}

func (t *transactionRepository) GetAll(ctx context.Context) ([]domain.Transaction, error) {
	var txs []domain.Transaction
	err := t.db.Find(&txs, nil)

	sort.Slice(txs, func(i, j int) bool {
		txi := txs[i]
		txj := txs[j]
		if txi.CreatedAt.Equal(txj.CreatedAt) {
			return txi.Type > txj.Type
		}
		return txi.CreatedAt.After(txj.CreatedAt)
	})

	return txs, err
}

func (t *transactionRepository) GetEventChannel() chan domain.TransactionEvent {
	return t.eventCh
}

func (t *transactionRepository) Stop() error {
	if err := t.db.Close(); err != nil {
		return err
	}
	close(t.eventCh)

	return nil
}
