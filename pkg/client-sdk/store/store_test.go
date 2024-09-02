package store_test

import (
	"context"
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	filestore "github.com/ark-network/ark/pkg/client-sdk/store/file"
	inmemorystore "github.com/ark-network/ark/pkg/client-sdk/store/inmemory"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestStore(t *testing.T) {
	key, _ := btcec.NewPrivateKey()
	ctx := context.Background()
	testStoreData := store.StoreData{
		AspUrl:              "localhost:7070",
		AspPubkey:           key.PubKey(),
		WalletType:          wallet.SingleKeyWallet,
		ClientType:          client.GrpcClient,
		Network:             common.LiquidRegTest,
		RoundLifetime:       512,
		RoundInterval:       10,
		UnilateralExitDelay: 512,
		MinRelayFee:         300,
	}

	tests := []struct {
		name string
	}{
		{
			name: store.InMemoryStore,
		},
		{
			name: store.FileStore,
		},
	}

	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var storeSvc store.ConfigStore
			var err error
			switch tt.name {
			case store.InMemoryStore:
				storeSvc, err = inmemorystore.NewConfigStore()
			case store.FileStore:
				storeSvc, err = filestore.NewConfigStore(t.TempDir())
			}
			require.NoError(t, err)
			require.NotNil(t, storeSvc)

			// Check empty data when store is empty.
			data, err := storeSvc.GetData(ctx)
			require.NoError(t, err)
			require.Nil(t, data)

			// Check no side effects when cleaning an empty store.
			err = storeSvc.CleanData(ctx)
			require.NoError(t, err)

			// Check add and retrieve data.
			err = storeSvc.AddData(ctx, testStoreData)
			require.NoError(t, err)

			data, err = storeSvc.GetData(ctx)
			require.NoError(t, err)
			require.Equal(t, testStoreData, *data)

			// Check clean and retrieve data.
			err = storeSvc.CleanData(ctx)
			require.NoError(t, err)

			data, err = storeSvc.GetData(ctx)
			require.NoError(t, err)
			require.Nil(t, data)

			// Check overwriting the store.
			err = storeSvc.AddData(ctx, testStoreData)
			require.NoError(t, err)
			err = storeSvc.AddData(ctx, testStoreData)
			require.NoError(t, err)
		})
	}
}
