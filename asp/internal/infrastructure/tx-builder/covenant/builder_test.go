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
			expectedNodesNum: 11,
		},
	}

	for _, f := range fixtures {
		tree, err := builder.BuildCongestionTree(poolTx, f.payments)
		require.NoError(t, err)
		require.Equal(t, f.expectedNodesNum, tree.NumberOfNodes())

		// check the root
		require.Len(t, tree[0], 1)
		require.Equal(t, poolTxID, tree[0][0].ParentTxid)

		// check the leaves
		for _, leaf := range tree.Leaves() {
			pset, err := psetv2.NewPsetFromBase64(leaf.Tx)
			require.NoError(t, err)

			require.Len(t, pset.Inputs, 1)
			require.Len(t, pset.Outputs, 1)

			inputTxID := chainhash.Hash(pset.Inputs[0].PreviousTxid).String()
			require.Equal(t, leaf.ParentTxid, inputTxID)
		}

		// check the nodes
		for i, level := range tree[:len(tree)-2] {
			for _, node := range level {
				pset, err := psetv2.NewPsetFromBase64(node.Tx)
				require.NoError(t, err)

				require.Len(t, pset.Inputs, 1)
				require.Len(t, pset.Outputs, 2)

				inputTxID := chainhash.Hash(pset.Inputs[0].PreviousTxid).String()
				require.Equal(t, node.ParentTxid, inputTxID)

				nextLevel := tree[i+1]
				childs := 0
				for _, n := range nextLevel {
					if n.ParentTxid == node.Txid {
						childs++
					}
				}
				require.Equal(t, 2, childs)
			}
		}
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
