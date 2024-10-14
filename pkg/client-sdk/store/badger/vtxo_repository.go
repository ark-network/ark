package badgerstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/ark-network/ark/pkg/client-sdk/store/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const (
	vtxoStoreDir = "vtxos"
)

type vtxoRepository struct {
	db *badgerhold.Store
}

func NewVtxoRepository(dir string, logger badger.Logger) (domain.VtxoRepository, error) {
	badgerDb, err := CreateDB(filepath.Join(dir, vtxoStoreDir), logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open round events store: %s", err)
	}
	return &vtxoRepository{
		db: badgerDb,
	}, nil
}

func (v *vtxoRepository) InsertVtxos(ctx context.Context, vtxos []domain.Vtxo) error {
	for _, vtxo := range vtxos {
		if err := v.db.Insert(vtxo.Key(), &vtxo); err != nil {
			return err
		}
	}
	return nil
}

func (v *vtxoRepository) UpdateVtxos(ctx context.Context, vtxos []domain.Vtxo) error {
	for _, vtxo := range vtxos {
		if err := v.db.Update(vtxo.Key(), &vtxo); err != nil {
			return err
		}
	}
	return nil
}

func (v *vtxoRepository) GetAll(
	ctx context.Context,
) (spendable []domain.Vtxo, spent []domain.Vtxo, err error) {
	var allVtxos []domain.Vtxo
	err = v.db.Find(&allVtxos, nil)
	if err != nil {
		return nil, nil, err
	}

	for _, vtxo := range allVtxos {
		if vtxo.Spent {
			spent = append(spent, vtxo)
		} else {
			spendable = append(spendable, vtxo)
		}
	}
	return
}

func (v *vtxoRepository) FindForKeys(
	ctx context.Context,
	keys []string,
) ([]domain.Vtxo, error) {
	var vtxos []domain.Vtxo
	for _, key := range keys {
		var vtxo domain.Vtxo
		err := v.db.Get(key, &vtxo)
		if err != nil {
			if errors.Is(err, badgerhold.ErrNotFound) {
				continue
			}

			return nil, err
		}
		vtxos = append(vtxos, vtxo)
	}

	return vtxos, nil
}

func (v *vtxoRepository) Stop() error {
	if err := v.db.Close(); err != nil {
		return err
	}

	return nil
}
