//go:build js && wasm
// +build js,wasm

package browser

import (
	"context"
	"syscall/js"

	"github.com/ark-network/ark/pkg/client-sdk/types"
)

// TODO: support vtxo and transaction stores localstorage impls.
type localStorageStore struct {
	configStore types.ConfigStore
}

func NewLocalStorageStore() types.Store {
	configStore := NewConfigStore(js.Global().Get("localStorage"))
	return &localStorageStore{configStore}
}

func (s *localStorageStore) ConfigStore() types.ConfigStore {
	return s.configStore
}

func (s *localStorageStore) VtxoStore() types.VtxoStore {
	return nil
}

func (s *localStorageStore) TransactionStore() types.TransactionStore {
	return nil
}

func (s *localStorageStore) Clean(ctx context.Context) {
	//nolint:all
	s.configStore.CleanData(ctx)
}

func (s *localStorageStore) Close() {}
