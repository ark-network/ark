package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/store/domain"
	filedb "github.com/ark-network/ark/pkg/client-sdk/store/file"
	inmemorydb "github.com/ark-network/ark/pkg/client-sdk/store/inmemory"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestStore(t *testing.T) {
	key, _ := btcec.NewPrivateKey()
	ctx := context.Background()
	testStoreData := domain.ConfigData{
		AspUrl:                     "localhost:7070",
		AspPubkey:                  key.PubKey(),
		WalletType:                 wallet.SingleKeyWallet,
		ClientType:                 client.GrpcClient,
		Network:                    common.LiquidRegTest,
		RoundLifetime:              512,
		RoundInterval:              10,
		UnilateralExitDelay:        512,
		Dust:                       1000,
		BoardingDescriptorTemplate: "tr(0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{ and(pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465), pk(USER)), and(older(604672), pk(USER)) })",
		ForfeitAddress:             "bcrt1qzvqj",
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

			var storeSvc domain.ConfigRepository
			var err error
			switch tt.name {
			case store.InMemoryStore:
				storeSvc, err = inmemorydb.NewConfig()
			case store.FileStore:
				storeSvc, err = filedb.NewConfig(t.TempDir())
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

func TestNewService(t *testing.T) {
	ctx := context.Background()
	testDir := t.TempDir()

	dbConfig := store.Config{
		ConfigStoreType:  store.FileStore,
		AppDataStoreType: store.Badger,
		BaseDir:          testDir,
	}

	service, err := store.NewService(dbConfig)
	require.NoError(t, err)
	require.NotNil(t, service)

	go func() {
		eventCh := service.AppDataRepository().TransactionRepository().GetEventChannel()
		for tx := range eventCh {
			log.Infof("Tx inserted: %d %v", tx.Tx.Amount, tx.Tx.Type)
		}
	}()

	txRepo := service.AppDataRepository().TransactionRepository()
	require.NotNil(t, txRepo)

	testTxs := []domain.Transaction{
		{
			RoundTxid: "tx1",
			Amount:    1000,
			Type:      domain.TxSent,
			CreatedAt: time.Now(),
		},
		{
			RoundTxid: "tx2",
			Amount:    2000,
			Type:      domain.TxReceived,
			CreatedAt: time.Now(),
		},
	}
	err = txRepo.InsertTransactions(ctx, testTxs)
	require.NoError(t, err)

	retrievedTxs, err := txRepo.GetAll(ctx)
	require.NoError(t, err)
	require.Len(t, retrievedTxs, 2)

	service.AppDataRepository().Stop()
}
