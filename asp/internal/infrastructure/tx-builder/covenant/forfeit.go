package txbuilder

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
	"github.com/vulpemventures/go-elements/transaction"
)

func createForfeitTx(
	connectorInput psetv2.InputArgs,
	connectorWitnessUtxo *transaction.TxOutput,
	vtxoInput psetv2.InputArgs,
	vtxoWitnessUtxo *transaction.TxOutput,
	vtxoTaprootTree *taproot.IndexedElementsTapScriptTree,
	aspScript []byte,
	net network.Network,
) (forfeitTx string, err error) {
	pset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return "", err
	}

	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return "", err
	}

	if err = updater.AddInputs([]psetv2.InputArgs{connectorInput, vtxoInput}); err != nil {
		return "", err
	}

	if err = updater.AddInWitnessUtxo(0, connectorWitnessUtxo); err != nil {
		return "", err
	}

	if err := updater.AddInSighashType(0, txscript.SigHashAll); err != nil {
		return "", err
	}

	if err = updater.AddInWitnessUtxo(1, vtxoWitnessUtxo); err != nil {
		return "", err
	}

	if err := updater.AddInSighashType(1, txscript.SigHashDefault); err != nil {
		return "", err
	}

	unspendableKeyBytes, _ := hex.DecodeString(unspendablePoint)
	unspendableKey, _ := secp256k1.ParsePubKey(unspendableKeyBytes)

	for _, proof := range vtxoTaprootTree.LeafMerkleProofs {
		tapScript := psetv2.NewTapLeafScript(proof, unspendableKey)
		if err := updater.AddInTapLeafScript(1, tapScript); err != nil {
			return "", err
		}
	}

	vtxoAmount, err := elementsutil.ValueFromBytes(vtxoWitnessUtxo.Value)
	if err != nil {
		return "", err
	}

	connectorAmount, err := elementsutil.ValueFromBytes(connectorWitnessUtxo.Value)
	if err != nil {
		return "", err
	}

	err = updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  net.AssetID,
			Amount: vtxoAmount + connectorAmount - 30,
			Script: aspScript,
		},
		{
			Asset:  net.AssetID,
			Amount: 30,
		},
	})
	if err != nil {
		return "", err
	}

	return pset.ToBase64()
}
