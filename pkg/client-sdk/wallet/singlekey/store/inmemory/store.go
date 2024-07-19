package inmemorystore

import (
	"sync"

	"github.com/ark-network/ark-sdk/store"
	walletstore "github.com/ark-network/ark-sdk/wallet/singlekey/store"
)

type inmemoryStore struct {
	store.Store
	data *walletstore.WalletData
	lock *sync.RWMutex
}

func NewWalletStore(store store.Store) (walletstore.WalletStore, error) {
	lock := &sync.RWMutex{}
	return &inmemoryStore{Store: store, lock: lock}, nil
}

func (s *inmemoryStore) AddWallet(data walletstore.WalletData) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data = &data
	return nil
}

func (s *inmemoryStore) GetWallet() (*walletstore.WalletData, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.data, nil
}
