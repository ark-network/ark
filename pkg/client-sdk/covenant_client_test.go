package arksdk

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/store/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCovenantArkClientListenToVtxoChan(t *testing.T) {
	var (
		ctx                              = context.Background()
		err                              error
		sdkRepo                          domain.SdkRepository
		txs                              []domain.Transaction
		spendableVtxosOld, spentVtxosOld []domain.Vtxo
	)

	sdkRepo, err = store.NewService(store.Config{
		ConfigStoreType:  store.FileStore,
		AppDataStoreType: store.Badger,
		BaseDir:          t.TempDir(),
	})
	require.NoError(t, err)
	by, err := hex.DecodeString("020000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(t, err)
	aspPubkey, err := secp256k1.ParsePubKey(by)

	arkC := arkClient{
		ConfigData: &domain.ConfigData{
			AspPubkey:     aspPubkey,
			RoundInterval: 20,
		},
		sdkRepository:  sdkRepo,
		sdkInitialized: false,
	}

	covenantArkClient := &covenantArkClient{
		arkClient: &arkC,
	}

	err = covenantArkClient.processVtxosAndTxs(ctx, nil, nil, []domain.Transaction{boardingTx1})
	require.NoError(t, err)

	txs, err = sdkRepo.AppDataRepository().TransactionRepository().GetAll(ctx)
	require.NoError(t, err)
	require.Len(t, txs, 1)

	spendableVtxosOld, spentVtxosOld, err = sdkRepo.AppDataRepository().VtxoRepository().GetAll(ctx)
	require.NoError(t, err)
	require.Len(t, spendableVtxosOld, 0)
	require.Len(t, spentVtxosOld, 0)

	spendableVtxo := []client.Vtxo{vtxo1}
	err = covenantArkClient.processVtxosAndTxs(ctx, spendableVtxo, nil, []domain.Transaction{boardingTx1})
	require.NoError(t, err)

	spentVtxo := []client.Vtxo{vtxo2}
	err = covenantArkClient.processVtxosAndTxs(ctx, spendableVtxo, spentVtxo, []domain.Transaction{boardingTx1})
	require.NoError(t, err)
}

var boardingTx1 = domain.Transaction{
	BoardingTxid: "ecba8b7280ceac8dfcc2c1bb34dd45c8783d09f970e9eb9d30ef436c91c036b6",
	Amount:       3000,
	Type:         domain.TxReceived,
	CreatedAt:    time.Now(),
}

var vtxo1 = client.Vtxo{
	Outpoint: client.Outpoint{
		Txid: "b8395c0fbc9cc6e56c172d6d3bebcf030fcc0bb5cf168361d515d62240e01010",
		VOut: 0,
	},
	Descriptor: "tr(0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{ and(pk(2763c97adba0ba950b65cbb78f306661a502509251614a1f7805a9facbbc0d22), pk(8ec2a71e3fb19b27b06237ed8453c8eafa7e326d22338446a91d439975c4ed50)), and(older(1024), pk(2763c97adba0ba950b65cbb78f306661a502509251614a1f7805a9facbbc0d22)) })",
	Amount:     99999000,
	RoundTxid:  "2af148e364f9e5e1dfd034ce8ac1a875ab3e341fef43ea29c551992a40150c20",
	ExpiresAt:  &time.Time{},
	SpentBy:    "",
}

var vtxo2 = client.Vtxo{
	Outpoint: client.Outpoint{
		Txid: "f17c9f987ae8061298a758dbdf7299793bc422244beb2c658e36c91e1f01bb7f",
		VOut: 0,
	},
	Descriptor: "tr(0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{ and(pk(2763c97adba0ba950b65cbb78f306661a502509251614a1f7805a9facbbc0d22), pk(8ec2a71e3fb19b27b06237ed8453c8eafa7e326d22338446a91d439975c4ed50)), and(older(1024), pk(2763c97adba0ba950b65cbb78f306661a502509251614a1f7805a9facbbc0d22)) })",
	Amount:     100000000,
	RoundTxid:  "ecba8b7280ceac8dfcc2c1bb34dd45c8783d09f970e9eb9d30ef436c91c036b6",
	ExpiresAt:  &time.Time{},
	SpentBy:    "2af148e364f9e5e1dfd034ce8ac1a875ab3e341fef43ea29c551992a40150c20",
}

func TestUpdateBoardingTxsState(t *testing.T) {
	now := time.Now()

	testCases := []struct {
		description        string
		allBoardingTxs     []domain.Transaction
		oldBoardingTxs     []domain.Transaction
		expectedNewTxs     []domain.Transaction
		expectedUpdatedTxs []domain.Transaction
	}{
		{
			description:        "No boarding transactions in both lists",
			allBoardingTxs:     []domain.Transaction{},
			oldBoardingTxs:     []domain.Transaction{},
			expectedNewTxs:     []domain.Transaction{},
			expectedUpdatedTxs: []domain.Transaction{},
		},
		{
			description: "All old boarding txs are still pending and present in new list",
			allBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx2", IsPending: true, CreatedAt: now},
			},
			oldBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx2", IsPending: true, CreatedAt: now},
			},
			expectedNewTxs:     []domain.Transaction{},
			expectedUpdatedTxs: []domain.Transaction{},
		},
		{
			description: "Some old boarding txs not in new list (should be marked as pending=false)",
			allBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
			},
			oldBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx2", IsPending: true, CreatedAt: now},
			},
			expectedNewTxs: []domain.Transaction{},
			expectedUpdatedTxs: []domain.Transaction{
				{BoardingTxid: "tx2", IsPending: false, CreatedAt: now},
			},
		},
		{
			description: "New boarding txs not present in old list",
			allBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx3", IsPending: true, CreatedAt: now},
			},
			oldBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
			},
			expectedNewTxs: []domain.Transaction{
				{BoardingTxid: "tx3", IsPending: true, CreatedAt: now},
			},
			expectedUpdatedTxs: []domain.Transaction{},
		},
		{
			description: "No overlap between old and new boarding txs",
			allBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx3", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx4", IsPending: true, CreatedAt: now},
			},
			oldBoardingTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx2", IsPending: true, CreatedAt: now},
			},
			expectedNewTxs: []domain.Transaction{
				{BoardingTxid: "tx3", IsPending: true, CreatedAt: now},
				{BoardingTxid: "tx4", IsPending: true, CreatedAt: now},
			},
			expectedUpdatedTxs: []domain.Transaction{
				{BoardingTxid: "tx1", IsPending: false, CreatedAt: now},
				{BoardingTxid: "tx2", IsPending: false, CreatedAt: now},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			newBoardingTxs, updatedOldBoardingTxs := updateBoardingTxsState(tc.allBoardingTxs, tc.oldBoardingTxs)
			assert.Equal(t, tc.expectedNewTxs, newBoardingTxs)
			assert.Equal(t, tc.expectedUpdatedTxs, updatedOldBoardingTxs)
		})
	}
}
