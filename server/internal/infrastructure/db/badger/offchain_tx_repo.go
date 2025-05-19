package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const offchainTxStoreDir = "offchaintx"

type offchainTxRepository struct {
	store *badgerhold.Store
}

func NewOffchainTxRepository(config ...interface{}) (domain.OffchainTxRepository, error) {
	if len(config) != 2 {
		return nil, fmt.Errorf("invalid config")
	}
	baseDir, ok := config[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid base directory")
	}
	var logger badger.Logger
	if config[1] != nil {
		logger, ok = config[1].(badger.Logger)
		if !ok {
			return nil, fmt.Errorf("invalid logger")
		}
	}

	var dir string
	if len(baseDir) > 0 {
		dir = filepath.Join(baseDir, offchainTxStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open offchain tx store: %s", err)
	}

	return &offchainTxRepository{store}, nil
}

func (r *offchainTxRepository) AddOrUpdateOffchainTx(
	ctx context.Context, offchainTx *domain.OffchainTx,
) error {
	return r.addOrUpdateOffchainTx(ctx, *offchainTx)
}

func (r *offchainTxRepository) GetOffchainTx(
	ctx context.Context, txid string,
) (*domain.OffchainTx, error) {
	return r.getOffchainTx(ctx, txid)
}

func (r *offchainTxRepository) Close() {
	// nolint:all
	r.store.Close()
}

func (r *offchainTxRepository) addOrUpdateOffchainTx(
	ctx context.Context, offchainTx domain.OffchainTx,
) error {
	var upsertFn func() error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		upsertFn = func() error {
			return r.store.TxUpsert(tx, offchainTx.VirtualTxid, offchainTx)
		}
	} else {
		upsertFn = func() error {
			return r.store.Upsert(offchainTx.VirtualTxid, offchainTx)
		}
	}
	if err := upsertFn(); err != nil {
		if errors.Is(err, badger.ErrConflict) {
			attempts := 1
			for errors.Is(err, badger.ErrConflict) && attempts <= maxRetries {
				time.Sleep(100 * time.Millisecond)
				err = upsertFn()
				attempts++
			}
		}
		return err
	}
	return nil
}

func (r *offchainTxRepository) getOffchainTx(
	ctx context.Context, txid string,
) (*domain.OffchainTx, error) {
	var offchainTx domain.OffchainTx
	var err error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxGet(tx, txid, &offchainTx)
	} else {
		err = r.store.Get(txid, &offchainTx)
	}
	if err != nil && err == badgerhold.ErrNotFound {
		return nil, fmt.Errorf("offchain tx %s not found", txid)
	}
	if offchainTx.Stage.Code == int(domain.OffchainTxUndefinedStage) {
		return nil, fmt.Errorf("offchain tx %s not found", txid)
	}

	return &offchainTx, nil
}
