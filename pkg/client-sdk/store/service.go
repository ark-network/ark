package store

import (
	badgerstore "github.com/ark-network/ark/pkg/client-sdk/store/badger"
	"github.com/ark-network/ark/pkg/client-sdk/store/domain"
	"github.com/ark-network/ark/pkg/client-sdk/store/file"
	"github.com/ark-network/ark/pkg/client-sdk/store/inmemory"
	"github.com/dgraph-io/badger/v4"
)

const (
	InMemoryStore = "inmemory"
	FileStore     = "file"
	Badger        = "badger"
)

type service struct {
	configRepository  domain.ConfigRepository
	appDataRepository domain.AppDataRepository
}

type Config struct {
	ConfigStoreType  string
	AppDataStoreType string

	BaseDir      string
	BadgerLogger badger.Logger
}

func NewService(storeConfig Config) (domain.SdkRepository, error) {
	var (
		configRepository      domain.ConfigRepository
		appDataRepository     domain.AppDataRepository
		transactionRepository domain.TransactionRepository
		err                   error

		dir          = storeConfig.BaseDir
		badgerLogger = storeConfig.BadgerLogger
	)

	switch storeConfig.ConfigStoreType {
	case InMemoryStore:
		configRepository, err = inmemorystore.NewConfig()
		if err != nil {
			return nil, err
		}
	case FileStore:
		configRepository, err = filestore.NewConfig(dir)
		if err != nil {
			return nil, err
		}
	}

	switch storeConfig.AppDataStoreType {
	case Badger:
		transactionRepository, err = badgerstore.NewTransactionRepository(
			dir,
			badgerLogger,
		)
		if err != nil {
			return nil, err
		}

		appDataRepository = badgerstore.NewAppDataRepository(
			transactionRepository,
		)
	}

	return &service{
		configRepository:  configRepository,
		appDataRepository: appDataRepository,
	}, nil
}

func (s *service) AppDataRepository() domain.AppDataRepository {
	return s.appDataRepository
}

func (s *service) ConfigRepository() domain.ConfigRepository {
	return s.configRepository
}
