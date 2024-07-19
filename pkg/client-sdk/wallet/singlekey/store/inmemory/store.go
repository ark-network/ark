package inmemorystore

import (
	"fmt"
	"sync"

	"github.com/ark-network/ark-sdk/store"
	walletstore "github.com/ark-network/ark-sdk/wallet/singlekey/store"
)

type inmemoryStore struct {
	store.Store
	data *walletstore.WalletData
	lock *sync.RWMutex
}

func NewWalletStore(args ...interface{}) (walletstore.WalletStore, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("invalid number of args")
	}
	store, ok := args[0].(store.Store)
	if !ok {
		return nil, fmt.Errorf("invalid store")
	}
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
