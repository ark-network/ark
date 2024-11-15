package db

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	badgerdb "github.com/ark-network/ark/server/internal/infrastructure/db/badger"
	sqlitedb "github.com/ark-network/ark/server/internal/infrastructure/db/sqlite"
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
	marketHourStoreTypes = map[string]func(...interface{}) (domain.MarketHourRepo, error){
		"sqlite": sqlitedb.NewMarketHourRepository,
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
	eventStore     domain.RoundEventRepository
	roundStore     domain.RoundRepository
	vtxoStore      domain.VtxoRepository
	marketHourRepo domain.MarketHourRepo
}

func NewService(config ServiceConfig) (ports.RepoManager, error) {
	eventStoreFactory, ok := eventStoreTypes[config.EventStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid event store type: %s", config.EventStoreType)
	}

	eventStore, err := eventStoreFactory(config.EventStoreConfig...)
	if err != nil {
		return nil, fmt.Errorf("failed to create event store: %w", err)
	}

	roundStoreFactory, ok := roundStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}

	vtxoStoreFactory, ok := vtxoStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}

	marketHourStoreFactory, ok := marketHourStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}

	if config.DataStoreType == "sqlite" {
		if err := migrateSqlite(config.DataStoreConfig); err != nil {
			return nil, fmt.Errorf("failed to migrate sqlite: %w", err)
		}
	}

	roundStore, err := roundStoreFactory(config.DataStoreConfig...)
	if err != nil {
		return nil, fmt.Errorf("failed to create round store: %w", err)
	}

	vtxoStore, err := vtxoStoreFactory(config.DataStoreConfig...)
	if err != nil {
		return nil, fmt.Errorf("failed to create vtxo store: %w", err)
	}

	marketHourRepo, err := marketHourStoreFactory(config.DataStoreConfig...)
	if err != nil {
		return nil, fmt.Errorf("failed to create market hour store: %w", err)
	}

	return &service{
		eventStore:     eventStore,
		roundStore:     roundStore,
		vtxoStore:      vtxoStore,
		marketHourRepo: marketHourRepo,
	}, nil
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

func (s *service) MarketHourRepo() domain.MarketHourRepo {
	return s.marketHourRepo
}

func (s *service) Close() {
	s.eventStore.Close()
	s.roundStore.Close()
	s.vtxoStore.Close()
	s.marketHourRepo.Close()
}

func migrateSqlite(config []interface{}) error {
	if len(config) != 1 {
		return errors.New("invalid config")
	}

	dbPath, ok := config[0].(string)
	if !ok {
		return errors.New("invalid config")
	}

	dbPath = filepath.Join(dbPath, sqliteDbFile)
	driver, err := sqlitemigrate.WithInstance(nil, &sqlitemigrate.Config{})
	if err != nil {
		return fmt.Errorf("failed to create sqlite driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://internal/infrastructure/db/sqlite/migration",
		"sqlite", driver,
	)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("failed to migrate up: %w", err)
	}

	return nil
}
