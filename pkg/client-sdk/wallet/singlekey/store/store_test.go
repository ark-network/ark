package store_test

import (
	"context"
	"testing"

	"github.com/ark-network/ark-sdk/store"
	walletstore "github.com/ark-network/ark-sdk/wallet/singlekey/store"
	filestore "github.com/ark-network/ark-sdk/wallet/singlekey/store/file"
	inmemorystore "github.com/ark-network/ark-sdk/wallet/singlekey/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestWalletStore(t *testing.T) {
	key, _ := btcec.NewPrivateKey()
	testWalletData := walletstore.WalletData{
		EncryptedPrvkey: make([]byte, 32),
		PasswordHash:    make([]byte, 32),
		Pubkey:          key.PubKey(),
	}

	tests := []struct {
		name     string
		getStore walletstore.WalletStoreFactory
		args     []interface{}
	}{
		{
			name:     store.InMemoryStore,
			getStore: inmemorystore.NewWalletStore,
			args:     []interface{}{newMockedStore()},
		},
		{
			name:     store.FileStore,
			getStore: filestore.NewWalletStore,
			args:     []interface{}{t.TempDir(), newMockedStore()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := tt.getStore(tt.args...)
			require.NoError(t, err)
			require.NotNil(t, store)

			// Check empty data when store is empty.
			walletData, err := store.GetWallet()
			require.NoError(t, err)
			require.Nil(t, walletData)

			// Check add and retrieve data.
			err = store.AddWallet(testWalletData)
			require.NoError(t, err)

			walletData, err = store.GetWallet()
			require.NoError(t, err)
			require.Equal(t, testWalletData, *walletData)

			// Check overwriting the store.
			err = store.AddWallet(testWalletData)
			require.NoError(t, err)
		})
	}
}

type mockedStore struct {
	mock.Mock
}

func newMockedStore() store.Store {
	return &mockedStore{}
}

func (m *mockedStore) AddData(ctx context.Context, data store.StoreData) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}
func (m *mockedStore) GetData(ctx context.Context) (*store.StoreData, error) {
	args := m.Called(ctx)

	var res *store.StoreData
	if a := args.Get(0); a != nil {
		res = a.(*store.StoreData)
	}
	return res, args.Error(1)
}

func (m *mockedStore) CleanData(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
