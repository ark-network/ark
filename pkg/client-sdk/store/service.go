package store

import (
	"fmt"

	filestore "github.com/ark-network/ark/pkg/client-sdk/store/file"
	inmemorystore "github.com/ark-network/ark/pkg/client-sdk/store/inmemory"
	kvstore "github.com/ark-network/ark/pkg/client-sdk/store/kv"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	log "github.com/sirupsen/logrus"
)

type service struct {
	configStore types.ConfigStore
	vtxoStore   types.VtxoStore
	txStore     types.TransactionStore
}

type Config struct {
	ConfigStoreType  string
	AppDataStoreType string

	BaseDir string
}

func NewStore(storeConfig Config) (types.Store, error) {
	var (
		configStore types.ConfigStore
		vtxoStore   types.VtxoStore
		txStore     types.TransactionStore
		err         error

		dir = storeConfig.BaseDir
	)

	switch storeConfig.ConfigStoreType {
	case types.InMemoryStore:
		configStore, err = inmemorystore.NewConfigStore()
	case types.FileStore:
		configStore, err = filestore.NewConfigStore(dir)
	default:
		err = fmt.Errorf("unknown config store type")
	}
	if err != nil {
		return nil, err
	}

	switch storeConfig.AppDataStoreType {
	case types.KVStore:
		logger := log.New()
		vtxoStore, err = kvstore.NewVtxoStore(dir, logger)
		if err != nil {
			return nil, err
		}
		txStore, err = kvstore.NewTransactionStore(dir, logger)
	default:
		err = fmt.Errorf("unknown appdata store type")
	}
	if err != nil {
		return nil, err
	}

	return &service{configStore, vtxoStore, txStore}, nil
}

func (s *service) ConfigStore() types.ConfigStore {
	return s.configStore
}

func (s *service) VtxoStore() types.VtxoStore {
	return s.vtxoStore
}

func (s *service) TransactionStore() types.TransactionStore {
	return s.txStore
}

func (s *service) Close() {
	s.configStore.Close()
	s.vtxoStore.Close()
	s.txStore.Close()
}
