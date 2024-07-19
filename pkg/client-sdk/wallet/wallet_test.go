package wallet_test

import (
	"context"
	"testing"

	"github.com/ark-network/ark-sdk/client"
	"github.com/ark-network/ark-sdk/store"
	inmemorystore "github.com/ark-network/ark-sdk/store/inmemory"
	"github.com/ark-network/ark-sdk/wallet"
	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestWallet(t *testing.T) {
	ctx := context.Background()
	key, _ := btcec.NewPrivateKey()
	password := "password"
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
		name      string
		getWallet wallet.WalletFactory
		args      []interface{}
	}{
		{
			name:      wallet.SingleKeyWallet,
			getWallet: wallet.NewSingleKeyWallet,
			args:      []interface{}{common.LiquidRegTest},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := inmemorystore.NewStore()
			require.NoError(t, err)
			require.NotNil(t, store)

			err = store.AddData(ctx, testStoreData)
			require.NoError(t, err)

			args := append(tt.args, store)
			walletSvc, err := tt.getWallet(args...)
			require.NoError(t, err)
			require.NotNil(t, walletSvc)

			key, err := walletSvc.Create(ctx, password, "")
			require.NoError(t, err)
			require.NotEmpty(t, key)

			offchainAddr, onchainAddr, err := walletSvc.NewAddress(ctx, false)
			require.NoError(t, err)
			require.NotEmpty(t, offchainAddr)
			require.NotEmpty(t, onchainAddr)

			offchainAddrs, onchainAddrs, redemptionAddrs, err := walletSvc.GetAddresses(ctx)
			require.NoError(t, err)
			require.Len(t, offchainAddrs, 1)
			require.Len(t, onchainAddrs, 1)
			require.Len(t, redemptionAddrs, 1)

			offchainAddr, onchainAddr, err = walletSvc.NewAddress(ctx, true)
			require.NoError(t, err)
			require.NotEmpty(t, offchainAddr)
			require.NotEmpty(t, onchainAddr)

			expectedNumOfAddresses := 2
			if tt.name == wallet.SingleKeyWallet {
				expectedNumOfAddresses = 1
			}

			offchainAddrs, onchainAddrs, redemptionAddrs, err = walletSvc.GetAddresses(ctx)
			require.NoError(t, err)
			require.Len(t, offchainAddrs, expectedNumOfAddresses)
			require.Len(t, onchainAddrs, expectedNumOfAddresses)
			require.Len(t, redemptionAddrs, expectedNumOfAddresses)

			num := 3
			offchainAddrs, onchainAddrs, err = walletSvc.NewAddresses(ctx, false, num)
			require.NoError(t, err)
			require.Len(t, offchainAddrs, num)
			require.Len(t, onchainAddrs, num)

			expectedNumOfAddresses += num
			if tt.name == wallet.SingleKeyWallet {
				expectedNumOfAddresses = 1
			}
			offchainAddrs, onchainAddrs, redemptionAddrs, err = walletSvc.GetAddresses(ctx)
			require.NoError(t, err)
			require.Len(t, offchainAddrs, expectedNumOfAddresses)
			require.Len(t, onchainAddrs, expectedNumOfAddresses)
			require.Len(t, redemptionAddrs, expectedNumOfAddresses)
		})
	}
}
