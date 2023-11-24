package txbuilder_test

import (
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	txbuilder "github.com/ark-network/ark/internal/infrastructure/tx-builder"
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

	return txbuilder.NewTxBuilder(key, &network.Regtest), nil
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

	payments := []domain.Payment{
		{
			Id: "0",
			Inputs: []domain.Vtxo{
				{
					Txid: "fd68e3c5796cc7db0a8036d486d5f625b6b2f2c014810ac020e1ac23e82c59d6",
					VOut: 0,
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
	}

	tree, err := builder.BuildCongestionTree(poolTx, payments)
	require.NoError(t, err)

	require.Equal(t, 3, len(tree))

	// decode all psbt

	psets := make([]*psetv2.Pset, 3)

	for i, pset := range tree {
		psets[i], err = psetv2.NewPsetFromBase64(pset)
		require.NoError(t, err)
	}

	require.Equal(t, 2, len(psets[0].Outputs))
	require.Equal(t, 1, len(psets[0].Inputs))

	// first tx input should be the pool tx shared output
	inputTxID0, err := chainhash.NewHash(psets[0].Inputs[0].PreviousTxid)
	require.NoError(t, err)
	require.Equal(t, poolTxID, inputTxID0.String())
	require.Equal(t, uint32(0), psets[0].Inputs[0].PreviousTxIndex)

	unsignedTx0, err := psets[0].UnsignedTx()
	require.NoError(t, err)

	txID0 := unsignedTx0.TxHash().String()

	// first tx input should be the first tx0 output
	require.Equal(t, 1, len(psets[1].Outputs))
	require.Equal(t, 1, len(psets[1].Inputs))
	inputTxID1, err := chainhash.NewHash(psets[1].Inputs[0].PreviousTxid)
	require.NoError(t, err)
	require.Equal(t, txID0, inputTxID1.String())
	require.Equal(t, uint32(0), psets[1].Inputs[0].PreviousTxIndex)
	// check the output amount (should be 600, the first receiver amount)
	require.Equal(t, uint64(600), psets[1].Outputs[0].Value)

	// second tx input should be the second tx0 output
	require.Equal(t, 1, len(psets[2].Outputs))
	require.Equal(t, 1, len(psets[2].Inputs))

	inputTxID2, err := chainhash.NewHash(psets[2].Inputs[0].PreviousTxid)
	require.NoError(t, err)
	require.Equal(t, txID0, inputTxID2.String())
	require.Equal(t, uint32(1), psets[2].Inputs[0].PreviousTxIndex)
	// check the output amount (should be 400, the second receiver amount)
	require.Equal(t, uint64(400), psets[2].Outputs[0].Value)
}

func TestBuildForfeitTxs(t *testing.T) {
	builder, err := createTestTxBuilder()
	require.NoError(t, err)

	poolTx, err := createTestPoolTx(1000, (450+500)*2)
	require.NoError(t, err)

	poolPset, err := psetv2.NewPsetFromBase64(poolTx)
	require.NoError(t, err)

	poolTxUnsigned, err := poolPset.UnsignedTx()
	require.NoError(t, err)

	poolTxID := poolTxUnsigned.TxHash().String()

	payments := []domain.Payment{
		{
			Id: "0",
			Inputs: []domain.Vtxo{
				{
					Txid: "fd68e3c5796cc7db0a8036d486d5f625b6b2f2c014810ac020e1ac23e82c59d6",
					VOut: 0,
				},
				{
					Txid: "fd68e3c5796cc7db0a8036d486d5f625b6b2f2c014810ac020e1ac23e82c59d6",
					VOut: 1,
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
	}

	connectors, forfeitTxs, err := builder.BuildForfeitTxs(poolTx, payments)
	require.NoError(t, err)

	require.Equal(t, 2, len(connectors))
	require.Equal(t, 2*2, len(forfeitTxs)) // should have inputs*numOfConnectors forfeits

	// decode and check connectors
	connectorsPsets := make([]*psetv2.Pset, 2)
	for i, pset := range connectors {
		connectorsPsets[i], err = psetv2.NewPsetFromBase64(pset)
		require.NoError(t, err)
	}

	// the first connector should have 1 input and 3 outputs
	require.Equal(t, 1, len(connectorsPsets[0].Inputs))
	require.Equal(t, 3, len(connectorsPsets[0].Outputs))
	// the input should be pool tx connectors output
	inputTxID0, err := chainhash.NewHash(connectorsPsets[0].Inputs[0].PreviousTxid)
	require.NoError(t, err)
	require.Equal(t, poolTxID, inputTxID0.String())
	require.Equal(t, uint32(1), connectorsPsets[0].Inputs[0].PreviousTxIndex)

	// the second connector should have 1 input and 2 outputs
	require.Equal(t, 1, len(connectorsPsets[1].Inputs))
	require.Equal(t, 2, len(connectorsPsets[1].Outputs))
	// must spend the first connector tx change (last output)
	unsignedFirstConnectorTx, err := connectorsPsets[0].UnsignedTx()
	require.NoError(t, err)
	firstConnectorTxID := unsignedFirstConnectorTx.TxHash().String()
	inputTxID1, err := chainhash.NewHash(connectorsPsets[1].Inputs[0].PreviousTxid)
	require.NoError(t, err)
	require.Equal(t, firstConnectorTxID, inputTxID1.String())
	require.Equal(t, uint32(3), connectorsPsets[1].Inputs[0].PreviousTxIndex)

	// decode and check forfeit txs
	forfeitTxsPsets := make([]*psetv2.Pset, 4)
	for i, pset := range forfeitTxs {
		forfeitTxsPsets[i], err = psetv2.NewPsetFromBase64(pset)
		require.NoError(t, err)
	}

	// each forfeit tx should have 2 inputs and 2 outputs
	for _, pset := range forfeitTxsPsets {
		require.Equal(t, 2, len(pset.Inputs))
		require.Equal(t, 2, len(pset.Outputs))
	}
}
