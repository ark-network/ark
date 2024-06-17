package db

import (
	"fmt"

	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	badgerdb "github.com/ark-network/ark/internal/infrastructure/db/badger"
	sqlitedb "github.com/ark-network/ark/internal/infrastructure/db/sqlite"
	dbtypes "github.com/ark-network/ark/internal/infrastructure/db/types"
)

var (
	eventStoreTypes = map[string]func(...interface{}) (dbtypes.EventStore, error){
		"badger": badgerdb.NewRoundEventRepository,
	}
	roundStoreTypes = map[string]func(...interface{}) (dbtypes.RoundStore, error){
		"badger": badgerdb.NewRoundRepository,
		"sqlite": sqlitedb.NewRoundRepository,
	}
	vtxoStoreTypes = map[string]func(...interface{}) (dbtypes.VtxoStore, error){
		"badger": badgerdb.NewVtxoRepository,
		"sqlite": sqlitedb.NewVtxoRepository,
	}
)

type ServiceConfig struct {
	EventStoreType string
	RoundStoreType string
	VtxoStoreType  string

	EventStoreConfig []interface{}
	RoundStoreConfig []interface{}
	VtxoStoreConfig  []interface{}
}

type service struct {
	eventStore dbtypes.EventStore
	roundStore dbtypes.RoundStore
	vtxoStore  dbtypes.VtxoStore
}

func NewService(config ServiceConfig) (ports.RepoManager, error) {
	eventStoreFactory, ok := eventStoreTypes[config.EventStoreType]
	if !ok {
		return nil, fmt.Errorf("event store type not supported")
	}
	roundStoreFactory, ok := roundStoreTypes[config.RoundStoreType]
	if !ok {
		return nil, fmt.Errorf("round store type not supported")
	}
	vtxoStoreFactory, ok := vtxoStoreTypes[config.VtxoStoreType]
	if !ok {
		return nil, fmt.Errorf("vtxo store type not supported")
	}

	eventStore, err := eventStoreFactory(config.EventStoreConfig...)
	if err != nil {
		return nil, fmt.Errorf("failed to open event store: %s", err)
	}
	roundStore, err := roundStoreFactory(config.RoundStoreConfig...)
	if err != nil {
		return nil, fmt.Errorf("failed to open round store: %s", err)
	}
	vtxoStore, err := vtxoStoreFactory(config.VtxoStoreConfig...)
	if err != nil {
		return nil, fmt.Errorf("failed to open vtxo store: %s", err)
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
