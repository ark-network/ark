package inmemorystore

import (
	"context"
	"sync"

	"github.com/ark-network/ark/pkg/client-sdk/store/domain"
)

type configStore struct {
	data *domain.ConfigData
	lock *sync.RWMutex
}

func NewConfig() (domain.ConfigRepository, error) {
	lock := &sync.RWMutex{}
	return &configStore{lock: lock}, nil
}

func (s *configStore) GetType() string {
	return "inmemory"
}

func (s *configStore) GetDatadir() string {
	return ""
}

func (s *configStore) AddData(
	_ context.Context, data domain.ConfigData,
) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data = &data
	return nil
}

func (s *configStore) GetData(_ context.Context) (*domain.ConfigData, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.data == nil {
		return nil, nil
	}

	return s.data, nil
}

func (s *configStore) CleanData(_ context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data = nil
	return nil
}
