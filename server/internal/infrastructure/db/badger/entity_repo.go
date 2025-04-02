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

const entityStoreDir = "entity"

type entityRepository struct {
	store *badgerhold.Store
}

type entities struct {
	Entities []domain.Entity
}

func NewEntityRepository(config ...interface{}) (domain.EntityRepository, error) {
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
		dir = filepath.Join(baseDir, entityStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open entity store: %s", err)
	}

	return &entityRepository{store}, nil
}

func (r *entityRepository) Add(ctx context.Context, entity domain.Entity, vtxoKeys []domain.VtxoKey) error {
	if len(vtxoKeys) == 0 {
		return fmt.Errorf("vtxo keys are required")
	}

	for _, vtxoKey := range vtxoKeys {
		var entities entities
		err := r.store.Get(vtxoKey.String(), &entities)
		if err == badgerhold.ErrNotFound {
			entities.Entities = []domain.Entity{entity}
		} else if err != nil {
			return fmt.Errorf("failed to get entity: %w", err)
		} else {
			// check if entity already exists
			for _, e := range entities.Entities {
				if e.NostrRecipient == entity.NostrRecipient {
					return nil
				}
			}

			entities.Entities = append(entities.Entities, entity)
		}

		if err := r.store.Upsert(vtxoKey.String(), entities); err != nil {
			if errors.Is(err, badger.ErrConflict) {
				attempts := 1
				for errors.Is(err, badger.ErrConflict) && attempts <= maxRetries {
					time.Sleep(100 * time.Millisecond)
					err = r.store.Upsert(vtxoKey.String(), entities)
					attempts++
				}
			}
			return err
		}
	}
	return nil
}

func (r *entityRepository) Get(ctx context.Context, key domain.VtxoKey) ([]domain.Entity, error) {
	var entities entities
	err := r.store.Get(key.String(), &entities)
	if err == badgerhold.ErrNotFound {
		return nil, fmt.Errorf("entities not found for key: %s", key)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get entity: %w", err)
	}
	return entities.Entities, nil
}

func (r *entityRepository) Delete(ctx context.Context, vtxoKeys []domain.VtxoKey) error {
	if len(vtxoKeys) == 0 {
		return fmt.Errorf("vtxo keys are required")
	}

	for _, vtxoKey := range vtxoKeys {
		if err := r.store.Delete(vtxoKey.String(), &entities{}); err != nil {
			if errors.Is(err, badgerhold.ErrNotFound) {
				continue
			}
			if errors.Is(err, badger.ErrConflict) {
				attempts := 1
				for errors.Is(err, badger.ErrConflict) && attempts <= maxRetries {
					time.Sleep(100 * time.Millisecond)
					err = r.store.Delete(vtxoKey.String(), &entities{})
					attempts++
				}
			}
			return err
		}
	}
	return nil
}
