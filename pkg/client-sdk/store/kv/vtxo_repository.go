package kvstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/dgraph-io/badger/v4"
	log "github.com/sirupsen/logrus"
	"github.com/timshannon/badgerhold/v4"
)

const (
	vtxoStoreDir = "vtxos"
)

type vtxoStore struct {
	db *badgerhold.Store
}

func NewVtxoStore(dir string, logger badger.Logger) (types.VtxoStore, error) {
	badgerDb, err := createDB(filepath.Join(dir, vtxoStoreDir), logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open round events store: %s", err)
	}
	return &vtxoStore{badgerDb}, nil
}

func (s *vtxoStore) AddVtxos(_ context.Context, vtxos []types.Vtxo) (int, error) {
	count := 0
	for _, vtxo := range vtxos {
		if err := s.db.Insert(vtxo.VtxoKey.String(), &vtxo); err != nil {
			if errors.Is(err, badgerhold.ErrKeyExists) {
				continue
			}
			return -1, err
		}
		count++
	}
	return count, nil
}

func (s *vtxoStore) UpdateVtxos(_ context.Context, vtxos []types.Vtxo) (int, error) {
	count := 0
	for _, vtxo := range vtxos {
		if err := s.db.Update(vtxo.VtxoKey.String(), &vtxo); err != nil {
			return -1, err
		}
		count++
	}
	return count, nil
}

func (s *vtxoStore) SpendVtxos(ctx context.Context, outpoints []types.VtxoKey, spentBy string) (int, error) {
	vtxos, err := s.GetVtxos(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	count := 0
	for _, vtxo := range vtxos {
		vtxo.Spent = true
		vtxo.SpentBy = spentBy
		if err := s.db.Update(vtxo.VtxoKey.String(), &vtxo); err != nil {
			return -1, err
		}
		count++
	}
	return count, nil
}

func (s *vtxoStore) GetAllVtxos(
	_ context.Context,
) (spendable, spent []types.Vtxo, err error) {
	var allVtxos []types.Vtxo
	err = s.db.Find(&allVtxos, nil)
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

func (s *vtxoStore) GetVtxos(
	_ context.Context, keys []types.VtxoKey,
) ([]types.Vtxo, error) {
	var vtxos []types.Vtxo
	for _, key := range keys {
		var vtxo types.Vtxo
		err := s.db.Get(key.String(), &vtxo)
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

func (s *vtxoStore) Close() {
	if err := s.db.Close(); err != nil {
		log.Debugf("error on closing db: %s", err)
	}
}
