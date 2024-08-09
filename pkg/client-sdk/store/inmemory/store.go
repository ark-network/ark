package inmemorystore

import (
	"context"
	"sync"

	"github.com/ark-network/ark/pkg/client-sdk/store"
)

type Store struct {
	data *store.StoreData
	lock *sync.RWMutex
}

func NewConfigStore() (store.ConfigStore, error) {
	lock := &sync.RWMutex{}
	return &Store{lock: lock}, nil
}

func (s *Store) GetType() string {
	return store.InMemoryStore
}

func (s *Store) GetDatadir() string {
	return ""
}

func (s *Store) AddData(
	_ context.Context, data store.StoreData,
) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data = &data
	return nil
}

func (s *Store) GetData(_ context.Context) (*store.StoreData, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.data == nil {
		return nil, nil
	}

	return s.data, nil
}

func (s *Store) CleanData(_ context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data = nil
	return nil
}
