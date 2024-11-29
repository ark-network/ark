package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const (
	marketHourStoreDir = "market_hour"
	marketHourKey      = "market_hour"
)

type marketHourRepository struct {
	store *badgerhold.Store
}

func NewMarketHourRepository(config ...interface{}) (domain.MarketHourRepo, error) {
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
		dir = filepath.Join(baseDir, marketHourStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open market hour store: %s", err)
	}

	return &marketHourRepository{store}, nil
}

func (r *marketHourRepository) Get(ctx context.Context) (*domain.MarketHour, error) {
	var marketHour domain.MarketHour
	err := r.store.Get("market_hour", &marketHour)
	if errors.Is(err, badgerhold.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get market hour: %w", err)
	}
	return &marketHour, nil
}

func (r *marketHourRepository) Upsert(ctx context.Context, marketHour domain.MarketHour) error {
	err := r.store.Upsert("market_hour", &marketHour)
	if err != nil {
		return fmt.Errorf("failed to upsert market hour: %w", err)
	}
	return nil
}

func (r *marketHourRepository) Close() {
	r.store.Close()
}
