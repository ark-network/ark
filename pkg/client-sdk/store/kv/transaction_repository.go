package kvstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"

	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/dgraph-io/badger/v4"
	log "github.com/sirupsen/logrus"
	"github.com/timshannon/badgerhold/v4"
)

const (
	transactionStoreDir = "transactions"
)

type txStore struct {
	db      *badgerhold.Store
	lock    *sync.Mutex
	eventCh chan types.Transaction
}

func NewTransactionStore(
	dir string, logger badger.Logger,
) (types.TransactionStore, error) {
	badgerDb, err := createDB(filepath.Join(dir, transactionStoreDir), logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open round events store: %s", err)
	}
	return &txStore{
		db:      badgerDb,
		lock:    &sync.Mutex{},
		eventCh: make(chan types.Transaction),
	}, nil
}

func (s *txStore) AddTransactions(
	_ context.Context, txs []types.Transaction,
) error {
	for _, tx := range txs {
		if err := s.db.Insert(tx.TransactionKey.String(), &tx); err != nil {
			if errors.Is(err, badgerhold.ErrKeyExists) {
				continue
			}
			return err
		}
		go func(tx types.Transaction) {
			s.sendEvent(tx)
		}(tx)
	}
	return nil
}

func (s *txStore) UpdateTransactions(
	_ context.Context, txs []types.Transaction,
) error {
	for _, tx := range txs {
		if err := s.db.Upsert(tx.TransactionKey.String(), &tx); err != nil {
			return err
		}
		go func(tx types.Transaction) {
			s.sendEvent(tx)
		}(tx)
	}
	return nil
}

func (s *txStore) GetAllTransactions(
	_ context.Context,
) ([]types.Transaction, error) {
	var txs []types.Transaction
	err := s.db.Find(&txs, nil)

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

func (s *txStore) GetTransactions(
	_ context.Context, txids []string,
) ([]types.Transaction, error) {
	txs := make([]types.Transaction, 0, len(txids))
	for _, txid := range txids {
		var tx types.Transaction
		if err := s.db.Get(txid, &tx); err != nil {
			if errors.Is(err, badgerhold.ErrNotFound) {
				continue
			}

			return nil, err
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

func (s *txStore) GetEventChannel() chan types.Transaction {
	return s.eventCh
}

func (s *txStore) Close() {
	if err := s.db.Close(); err != nil {
		log.Debugf("error on closing transactions db: %s", err)
	}
	close(s.eventCh)
}

func (s *txStore) sendEvent(event types.Transaction) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.eventCh <- event
}
