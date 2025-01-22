package db

import (
	"embed"
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
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed sqlite/migration/*
var migrations embed.FS

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
	noteStoreTypes = map[string]func(...interface{}) (domain.NoteRepository, error){
		"badger": badgerdb.NewNoteRepository,
		"sqlite": sqlitedb.NewNoteRepository,
	}
	entityStoreTypes = map[string]func(...interface{}) (domain.EntityRepository, error){
		"badger": badgerdb.NewEntityRepository,
		"sqlite": sqlitedb.NewEntityRepository,
	}
	marketHourStoreTypes = map[string]func(...interface{}) (domain.MarketHourRepo, error){
		"badger": badgerdb.NewMarketHourRepository,
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
	noteStore      domain.NoteRepository
	entityStore    domain.EntityRepository
	marketHourRepo domain.MarketHourRepo
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
	noteStoreFactory, ok := noteStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("note store type not supported")
	}
	entityStoreFactory, ok := entityStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("entity store type not supported")
	}
	marketHourStoreFactory, ok := marketHourStoreTypes[config.DataStoreType]
	if !ok {
		return nil, fmt.Errorf("invalid data store type: %s", config.DataStoreType)
	}

	var eventStore domain.RoundEventRepository
	var roundStore domain.RoundRepository
	var vtxoStore domain.VtxoRepository
	var noteStore domain.NoteRepository
	var entityStore domain.EntityRepository
	var marketHourRepo domain.MarketHourRepo
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
		entityStore, err = entityStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to open entity store: %s", err)
		}
		noteStore, err = noteStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to open note store: %s", err)
		}
		marketHourRepo, err = marketHourStoreFactory(config.DataStoreConfig...)
		if err != nil {
			return nil, fmt.Errorf("failed to create market hour store: %w", err)
		}
	case "sqlite":
		if len(config.DataStoreConfig) != 1 {
			return nil, fmt.Errorf("invalid data store config")
		}

		baseDir, ok := config.DataStoreConfig[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid base directory")
		}

		dbFile := filepath.Join(baseDir, sqliteDbFile)
		db, err := sqlitedb.OpenDb(dbFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open db: %s", err)
		}

		driver, err := sqlitemigrate.WithInstance(db, &sqlitemigrate.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to init driver: %s", err)
		}

		source, err := iofs.New(migrations, "sqlite/migration")
		if err != nil {
			return nil, fmt.Errorf("failed to embed migrations: %s", err)
		}

		m, err := migrate.NewWithInstance("iofs", source, "arkdb", driver)
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
		entityStore, err = entityStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open entity store: %s", err)
		}
		noteStore, err = noteStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to open note store: %s", err)
		}

		marketHourRepo, err = marketHourStoreFactory(db)
		if err != nil {
			return nil, fmt.Errorf("failed to create market hour store: %w", err)
		}
	}

	return &service{
		eventStore:     eventStore,
		roundStore:     roundStore,
		vtxoStore:      vtxoStore,
		noteStore:      noteStore,
		entityStore:    entityStore,
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

func (s *service) Notes() domain.NoteRepository {
	return s.noteStore
}

func (s *service) Entities() domain.EntityRepository {
	return s.entityStore
}

func (s *service) MarketHourRepo() domain.MarketHourRepo {
	return s.marketHourRepo
}

func (s *service) Close() {
	s.eventStore.Close()
	s.roundStore.Close()
	s.vtxoStore.Close()
	s.noteStore.Close()
	s.marketHourRepo.Close()
}
