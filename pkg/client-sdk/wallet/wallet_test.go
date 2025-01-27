package wallet_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	inmemorystore "github.com/ark-network/ark/pkg/client-sdk/store/inmemory"
	sdktypes "github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	singlekeywallet "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey"
	inmemorywalletstore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestWallet(t *testing.T) {
	ctx := context.Background()
	key, _ := btcec.NewPrivateKey()
	password := "password"
	testStoreData := sdktypes.Config{
		ServerUrl:                  "localhost:7070",
		ServerPubKey:               key.PubKey(),
		WalletType:                 wallet.SingleKeyWallet,
		ClientType:                 client.GrpcClient,
		Network:                    common.LiquidRegTest,
		VtxoTreeExpiry:             common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 512},
		RoundInterval:              10,
		UnilateralExitDelay:        common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 512},
		Dust:                       1000,
		BoardingDescriptorTemplate: "tr(0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{ and(pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465), pk(USER)), and(older(604672), pk(USER)) })",
		ForfeitAddress:             "bcrt1qzvqj",
	}
	tests := []struct {
		name  string
		chain string
		args  []interface{}
	}{
		{
			name:  "liquid" + wallet.SingleKeyWallet,
			chain: "liquid",
			args:  []interface{}{common.LiquidRegTest},
		},
		{
			name:  "bitcoin" + wallet.SingleKeyWallet,
			chain: "bitcoin",
			args:  []interface{}{common.LiquidRegTest},
		},
	}

	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, err := inmemorystore.NewConfigStore()
			require.NoError(t, err)
			require.NotNil(t, store)

			err = store.AddData(ctx, testStoreData)
			require.NoError(t, err)

			walletStore, err := inmemorywalletstore.NewWalletStore()
			require.NoError(t, err)
			require.NotNil(t, walletStore)

			var walletSvc wallet.WalletService
			if tt.chain == "liquid" {
				walletSvc, err = singlekeywallet.NewLiquidWallet(store, walletStore)
			} else {
				walletSvc, err = singlekeywallet.NewBitcoinWallet(store, walletStore)
			}
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
			if strings.Contains(tt.name, wallet.SingleKeyWallet) {
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
			if strings.Contains(tt.name, wallet.SingleKeyWallet) {
				expectedNumOfAddresses = 1
			}
			offchainAddrs, onchainAddrs, redemptionAddrs, err = walletSvc.GetAddresses(ctx)
			require.NoError(t, err)
			require.Len(t, offchainAddrs, expectedNumOfAddresses)
			require.Len(t, onchainAddrs, expectedNumOfAddresses)
			require.Len(t, redemptionAddrs, expectedNumOfAddresses)

			// Check no password is required to unlock if wallet is already unlocked.
			alreadyUnlocked, err := walletSvc.Unlock(ctx, password)
			require.NoError(t, err)
			require.False(t, alreadyUnlocked)

			alreadyUnlocked, err = walletSvc.Unlock(ctx, "")
			require.NoError(t, err)
			require.True(t, alreadyUnlocked)

			// Check no password is required to lock if wallet is already locked.
			err = walletSvc.Lock(ctx, password)
			require.NoError(t, err)

			err = walletSvc.Lock(ctx, "")
			require.NoError(t, err)

			locked := walletSvc.IsLocked()
			require.True(t, locked)

			_, err = walletSvc.Unlock(ctx, password)
			require.NoError(t, err)

			locked = walletSvc.IsLocked()
			require.False(t, locked)
		})
	}
}
