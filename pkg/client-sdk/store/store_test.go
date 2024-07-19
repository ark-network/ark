package store_test

import (
	"context"
	"testing"

	"github.com/ark-network/ark-sdk/client"
	"github.com/ark-network/ark-sdk/store"
	filestore "github.com/ark-network/ark-sdk/store/file"
	inmemorystore "github.com/ark-network/ark-sdk/store/inmemory"
	"github.com/ark-network/ark-sdk/wallet"
	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestStore(t *testing.T) {
	key, _ := btcec.NewPrivateKey()
	ctx := context.Background()
	testStoreData := store.StoreData{
		AspUrl:              "localhost:8080",
		AspPubkey:           key.PubKey(),
		WalletType:          wallet.SingleKeyWallet,
		ClientType:          client.GrpcClient,
		ExplorerURL:         "https://example.com",
		Network:             common.LiquidRegTest,
		RoundLifetime:       512,
		UnilateralExitDelay: 512,
		MinRelayFee:         300,
	}

	tests := []struct {
		name     string
		getStore store.StoreFactory
	}{
		{
			name:     store.InMemoryStore,
			getStore: inmemorystore.NewStore,
		},
		{
			name:     store.FileStore,
			getStore: filestore.NewStore,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			datadir := t.TempDir()
			store, err := tt.getStore(datadir)
			require.NoError(t, err)
			require.NotNil(t, store)

			// Check empty data when store is empty.
			data, err := store.GetData(ctx)
			require.NoError(t, err)
			require.Nil(t, data)

			// Check no side effects when cleaning an empty store.
			err = store.CleanData(ctx)
			require.NoError(t, err)

			// Check add and retrieve data.
			err = store.AddData(ctx, testStoreData)
			require.NoError(t, err)

			data, err = store.GetData(ctx)
			require.NoError(t, err)
			require.Equal(t, testStoreData, *data)

			// Check clean and retrieve data.
			err = store.CleanData(ctx)
			require.NoError(t, err)

			data, err = store.GetData(ctx)
			require.NoError(t, err)
			require.Nil(t, data)

			// Check overwriting the store.
			err = store.AddData(ctx, testStoreData)
			require.NoError(t, err)
			err = store.AddData(ctx, testStoreData)
			require.NoError(t, err)
		})
	}
}
