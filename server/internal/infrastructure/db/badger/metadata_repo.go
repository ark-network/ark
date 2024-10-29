package badgerdb

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const metadataStoreDir = "metadata"

type metadataRepository struct {
	store *badgerhold.Store
}

func NewMetadataRepository(config ...interface{}) (domain.MetadataRepository, error) {
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
		dir = filepath.Join(baseDir, metadataStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open metadata store: %s", err)
	}

	return &metadataRepository{store}, nil
}

func (r *metadataRepository) AddOrUpdate(ctx context.Context, metadata domain.Metadata, vtxoKeys []domain.VtxoKey) error {
	if len(vtxoKeys) == 0 {
		return fmt.Errorf("vtxo keys are required")
	}

	for _, vtxoKey := range vtxoKeys {
		err := r.store.Upsert(vtxoKey.String(), metadata)
		if err != nil {
			return fmt.Errorf("failed to upsert metadata: %w", err)
		}
	}
	return nil
}

func (r *metadataRepository) Get(ctx context.Context, key domain.VtxoKey) (*domain.Metadata, error) {
	var metadata domain.Metadata
	err := r.store.Get(key.String(), &metadata)
	if err == badgerhold.ErrNotFound {
		return nil, fmt.Errorf("metadata not found for key: %s", key)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata: %w", err)
	}
	return &metadata, nil
}

func (r *metadataRepository) Delete(ctx context.Context, vtxoKeys []domain.VtxoKey) error {
	if len(vtxoKeys) == 0 {
		return fmt.Errorf("vtxo keys are required")
	}

	for _, vtxoKey := range vtxoKeys {
		err := r.store.Delete(vtxoKey.String(), &domain.Metadata{})
		if err == badgerhold.ErrNotFound {
			return fmt.Errorf("metadata not found for key: %s", vtxoKey)
		}
		if err != nil {
			return fmt.Errorf("failed to delete metadata: %w", err)
		}
	}
	return nil
}
