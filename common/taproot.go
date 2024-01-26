package common

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/vulpemventures/go-elements/psetv2"
)

// TaprootPreimage computes the hash for witness v1 input of a pset
// it implicitly assumes that the pset has witnessUtxo fields populated
func TaprootPreimage(
	genesisBlockHash *chainhash.Hash,
	pset *psetv2.Pset,
	inputIndex int,
	leafHash *chainhash.Hash,
) ([]byte, error) {
	prevoutScripts := make([][]byte, 0)
	prevoutAssets := make([][]byte, 0)
	prevoutValues := make([][]byte, 0)

	for i, input := range pset.Inputs {
		if input.WitnessUtxo == nil {
			return nil, fmt.Errorf("missing witness utxo on input #%d", i)
		}

		prevoutScripts = append(prevoutScripts, input.WitnessUtxo.Script)
		prevoutAssets = append(prevoutAssets, input.WitnessUtxo.Asset)
		prevoutValues = append(prevoutValues, input.WitnessUtxo.Value)
	}

	utx, err := pset.UnsignedTx()
	if err != nil {
		return nil, err
	}

	preimage := utx.HashForWitnessV1(
		inputIndex,
		prevoutScripts,
		prevoutAssets,
		prevoutValues,
		pset.Inputs[inputIndex].SigHashType,
		genesisBlockHash,
		leafHash,
		nil,
	)
	return preimage[:], nil
}
