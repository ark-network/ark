package txbuilder_test

import (
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	txbuilder "github.com/ark-network/ark/internal/infrastructure/tx-builder/dummy"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
)

const (
	testingKey = "apub1qgvdtj5ttpuhkldavhq8thtm5auyk0ec4dcmrfdgu0u5hgp9we22v3hrs4x"
)

func createTestTxBuilder() (ports.TxBuilder, error) {
	_, key, err := common.DecodePubKey(testingKey)
	if err != nil {
		return nil, err
	}

	return txbuilder.NewTxBuilder(key, common.MainNet), nil
}

func createTestPoolTx(sharedOutputAmount, numberOfInputs uint64) (string, error) {
	_, key, err := common.DecodePubKey(testingKey)
	if err != nil {
		return "", err
	}

	payment := payment.FromPublicKey(key, &network.Regtest, nil)
	addr, err := payment.WitnessPubKeyHash()
	if err != nil {
		return "", err
	}

	script, err := address.ToOutputScript(addr)
	if err != nil {
		return "", err
	}

	pset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return "", err
	}

	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return "", err
	}

	err = updater.AddInputs([]psetv2.InputArgs{
		{
			Txid:    "2f8f5733734fd44d581976bd3c1aee098bd606402df2ce02ce908287f1d5ede4",
			TxIndex: 0,
		},
	})
	if err != nil {
		return "", err
	}

	connectorsAmount := numberOfInputs * (450 + 500)

	err = updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  network.Regtest.AssetID,
			Amount: sharedOutputAmount,
			Script: script,
		},
		{
			Asset:  network.Regtest.AssetID,
			Amount: connectorsAmount,
			Script: script,
		},
		{
			Asset:  network.Regtest.AssetID,
			Amount: 500,
		},
	})
	if err != nil {
		return "", err
	}

	return pset.ToBase64()
}

func TestBuildCongestionTree(t *testing.T) {
	builder, err := createTestTxBuilder()
	require.NoError(t, err)

	poolTx, err := createTestPoolTx(1000, (450+500)*1)
	require.NoError(t, err)

	poolPset, err := psetv2.NewPsetFromBase64(poolTx)
	require.NoError(t, err)

	poolTxUnsigned, err := poolPset.UnsignedTx()
	require.NoError(t, err)

	poolTxID := poolTxUnsigned.TxHash().String()

	fixtures := []struct {
		payments         []domain.Payment
		expectedNodesNum int // 2*len(receivers)-1
	}{
		{
			payments: []domain.Payment{
				{
					Id: "0",
					Inputs: []domain.Vtxo{
						{
							VtxoKey: domain.VtxoKey{
								Txid: "fd68e3c5796cc7db0a8036d486d5f625b6b2f2c014810ac020e1ac23e82c59d6",
								VOut: 0,
							},
							Receiver: domain.Receiver{
								Pubkey: "apub1qgvdtj5ttpuhkldavhq8thtm5auyk0ec4dcmrfdgu0u5hgp9we22v3hrs4x",
								Amount: 600,
							},
						},
					},
					Receivers: []domain.Receiver{
						{
							Pubkey: "apub1qgvdtj5ttpuhkldavhq8thtm5auyk0ec4dcmrfdgu0u5hgp9we22v3hrs4x",
							Amount: 600,
						},
						{
							Pubkey: "apub1qgvdtj5ttpuhkldavhq8thtm5auyk0ec4dcmrfdgu0u5hgp9we22v3hrs4x",
							Amount: 400,
						},
					},
				},
			},
			expectedNodesNum: 3,
		},
	}

	for _, f := range fixtures {
		tree, err := builder.BuildCongestionTree(poolTx, f.payments)
		require.NoError(t, err)
		require.Len(t, tree.NumberOfNodes(), f.expectedNodesNum)

		// check the leaves
		for _, leaf := range tree.Leaves() {
			pset, err := psetv2.NewPsetFromBase64(leaf.Tx)
			require.NoError(t, err)

			require.Len(t, pset.Inputs, 1)
			require.Len(t, pset.Outputs, 1)

			inputTxID := chainhash.Hash(pset.Inputs[0].PreviousTxid).String()
			require.Equal(t, leaf.ParentTxid, inputTxID)
		}

		// first tx input  should be the pool tx shared output
		inputTxID0, err := chainhash.NewHash(psets[0].Inputs[0].PreviousTxid)
		require.NoError(t, err)
		require.Equal(t, poolTxID, inputTxID0.String())
		require.Equal(t, uint32(0), psets[0].Inputs[0].PreviousTxIndex)

		unsignedTx0, err := psets[0].UnsignedTx()
		require.NoError(t, err)

		txID0 := unsignedTx0.TxHash().String()

		// first tx input should be the first tx0 output
		require.Len(t, psets[1].Inputs, 1)
		require.Len(t, psets[1].Outputs, 1)
		inputTxID1, err := chainhash.NewHash(psets[1].Inputs[0].PreviousTxid)
		require.NoError(t, err)
		require.Equal(t, txID0, inputTxID1.String())
		require.Equal(t, uint32(0), psets[1].Inputs[0].PreviousTxIndex)
		// check the output amount (should be 600, the first receiver amount)
		require.Equal(t, uint64(600), psets[1].Outputs[0].Value)

		// second tx input should be the second tx0 output
		require.Len(t, psets[2].Inputs, 1)
		require.Len(t, psets[2].Outputs, 1)

		inputTxID2, err := chainhash.NewHash(psets[2].Inputs[0].PreviousTxid)
		require.NoError(t, err)
		require.Equal(t, txID0, inputTxID2.String())
		require.Equal(t, uint32(1), psets[2].Inputs[0].PreviousTxIndex)
		// check the output amount (should be 400, the second receiver amount)
		require.Equal(t, uint64(400), psets[2].Outputs[0].Value)
	}
}

func TestBuildForfeitTxs(t *testing.T) {
	builder, err := createTestTxBuilder()
	require.NoError(t, err)

	poolTx, err := createTestPoolTx(1000, 450*2)
	require.NoError(t, err)

	poolPset, err := psetv2.NewPsetFromBase64(poolTx)
	require.NoError(t, err)

	poolTxUnsigned, err := poolPset.UnsignedTx()
	require.NoError(t, err)

	poolTxID := poolTxUnsigned.TxHash().String()

	fixtures := []struct {
		payments                []domain.Payment
		expectedNumOfForfeitTxs int
		expectedNumOfConnectors int
	}{
		{
			payments: []domain.Payment{
				{
					Id: "0",
					Inputs: []domain.Vtxo{
						{
							VtxoKey: domain.VtxoKey{
								Txid: "fd68e3c5796cc7db0a8036d486d5f625b6b2f2c014810ac020e1ac23e82c59d6",
								VOut: 0,
							},
							Receiver: domain.Receiver{
								Pubkey: "apub1qgvdtj5ttpuhkldavhq8thtm5auyk0ec4dcmrfdgu0u5hgp9we22v3hrs4x",
								Amount: 600,
							},
						},
						{
							VtxoKey: domain.VtxoKey{
								Txid: "fd68e3c5796cc7db0a8036d486d5f625b6b2f2c014810ac020e1ac23e82c59d6",
								VOut: 1,
							},
							Receiver: domain.Receiver{
								Pubkey: "apub1qgvdtj5ttpuhkldavhq8thtm5auyk0ec4dcmrfdgu0u5hgp9we22v3hrs4x",
								Amount: 400,
							},
						},
					},
					Receivers: []domain.Receiver{
						{
							Pubkey: "apub1qgvdtj5ttpuhkldavhq8thtm5auyk0ec4dcmrfdgu0u5hgp9we22v3hrs4x",
							Amount: 600,
						},
						{
							Pubkey: "apub1qgvdtj5ttpuhkldavhq8thtm5auyk0ec4dcmrfdgu0u5hgp9we22v3hrs4x",
							Amount: 400,
						},
					},
				},
			},
			expectedNumOfForfeitTxs: 4,
			expectedNumOfConnectors: 1,
		},
	}

	for _, f := range fixtures {
		connectors, forfeitTxs, err := builder.BuildForfeitTxs(poolTx, f.payments)
		require.NoError(t, err)

		require.Len(t, connectors, f.expectedNumOfConnectors)
		require.Len(t, forfeitTxs, f.expectedNumOfForfeitTxs)

		// decode and check connectors
		connectorsPsets := make([]*psetv2.Pset, 0, f.expectedNumOfConnectors)
		for _, pset := range connectors {
			p, err := psetv2.NewPsetFromBase64(pset)
			require.NoError(t, err)
			connectorsPsets = append(connectorsPsets, p)
		}

		for i, pset := range connectorsPsets {
			require.Len(t, pset.Inputs, 1)
			require.Len(t, pset.Outputs, 2)

			expectedInputTxid := poolTxID
			expectedInputVout := uint32(1)
			if i > 0 {
				tx, err := connectorsPsets[i-1].UnsignedTx()
				require.NoError(t, err)
				require.NotNil(t, tx)
				expectedInputTxid = tx.TxHash().String()
			}

			inputTxid := chainhash.Hash(pset.Inputs[0].PreviousTxid).String()
			require.Equal(t, expectedInputTxid, inputTxid)
			require.Equal(t, expectedInputVout, pset.Inputs[0].PreviousTxIndex)
		}

		// decode and check forfeit txs
		forfeitTxsPsets := make([]*psetv2.Pset, 0, f.expectedNumOfForfeitTxs)
		for _, pset := range forfeitTxs {
			p, err := psetv2.NewPsetFromBase64(pset)
			require.NoError(t, err)
			forfeitTxsPsets = append(forfeitTxsPsets, p)
		}

		// each forfeit tx should have 2 inputs and 2 outputs
		for _, pset := range forfeitTxsPsets {
			require.Len(t, pset.Inputs, 2)
			require.Len(t, pset.Outputs, 1)
		}
	}
}
