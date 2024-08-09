package db

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	badgerdb "github.com/ark-network/ark/internal/infrastructure/db/badger"
	sqlitedb "github.com/ark-network/ark/internal/infrastructure/db/sqlite"
	"github.com/golang-migrate/migrate/v4"
	sqlitemigrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

var (
	eventStoreTypes = map[string]func(...interface{}) (domain.RoundEventRepository, error){
		"badger": badgerdb.NewRoundEventRepository,
	}
	roundStoreTypes = map[string]func(...interface{}) (domain.RoundRepository, error){
		"badger": badgerdb.NewRoundRepository,
		"sqlite": sqlitedb.NewRoundRepository,
	}
	vtxoStoreTypes = map[string]func(...interface{}) (domain.VtxoRepository, error){
		"badger": badgerdb.NewVtxoRepository,
		"sqlite": sqlitedb.NewVtxoRepository,
	}
)

const (
	sqliteDbFile = "sqlite.db"
)

type ServiceConfig struct {
	EventStoreType string
	DataStoreType  string

	EventStoreConfig []interface{}
	DataStoreConfig  []interface{}
}

type service struct {
	eventStore domain.RoundEventRepository
	roundStore domain.RoundRepository
	vtxoStore  domain.VtxoRepository
}

func NewService(config ServiceConfig) (ports.RepoManager, error) {
	eventStoreFactory, ok := eventStoreTypes[config.EventStoreType]
	if !ok {
		return nil, fmt.Errorf("event store type not supported")
	}
	roundStoreFactory, ok := roundStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("round store type not supported")
	}
	vtxoStoreFactory, ok := vtxoStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("vtxo store type not supported")
	}

	var eventStore domain.RoundEventRepository
	var roundStore domain.RoundRepository
	var vtxoStore domain.VtxoRepository
	var err error

	switch config.EventStoreType {
	case "badger":
		eventStore, err = eventStoreFactory(config.EventStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to open event store: %s", err)
		}
	default:
		return nil, fmt.Errorf("unknown event store db type")
	}

	switch config.DataStoreType {
	case "badger":
		roundStore, err = roundStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to open round store: %s", err)
		}
		vtxoStore, err = vtxoStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to open vtxo store: %s", err)
		}
	case "sqlite":
		if len(config.DataStoreConfig) != 2 {
			return nil, fmt.Errorf("invalid data store config")
		}

		baseDir, ok := config.DataStoreConfig[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid base directory")
		}

		migrationPath, ok := config.DataStoreConfig[1].(string)
		if !ok {
			return nil, fmt.Errorf("invalid migration path")
		}

		dbFile := filepath.Join(baseDir, sqliteDbFile)
		db, err := sqlitedb.OpenDb(dbFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open db: %s", err)
		}

		driver, err := sqlitemigrate.WithInstance(db, &sqlitemigrate.Config{})
		if err != nil {
			return nil, err
		}

		m, err := migrate.NewWithDatabaseInstance(
			migrationPath,
			"arkdb",
			driver,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create migration instance: %s", err)
		}

		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return nil, fmt.Errorf("failed to run migrations: %s", err)
		}

		roundStore, err = roundStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open round store: %s", err)
		}
		vtxoStore, err = vtxoStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open vtxo store: %s", err)
		}

	}

	return &service{eventStore, roundStore, vtxoStore}, nil
}

func (s *service) RegisterEventsHandler(handler func(round *domain.Round)) {
	s.eventStore.RegisterEventsHandler(handler)
}

func (s *service) Events() domain.RoundEventRepository {
	return s.eventStore
}

func (s *service) Rounds() domain.RoundRepository {
	return s.roundStore
}

func (s *service) Vtxos() domain.VtxoRepository {
	return s.vtxoStore
}

func (s *service) Close() {
	s.eventStore.Close()
	s.roundStore.Close()
	s.vtxoStore.Close()
}
