package txbuilder

import (
	"fmt"

	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/psetv2"
)

func sweepTransaction(
	wallet ports.WalletService,
	input psetv2.Input,
	receivingAddress string,
	fees uint64,
) (string, error) {
	sweepPset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return "", err
	}

	updater, err := psetv2.NewUpdater(sweepPset)
	if err != nil {
		return "", err
	}

	updater.AddInputs([]psetv2.InputArgs{
		{
			Txid:     chainhash.Hash(input.PreviousTxid).String(),
			TxIndex:  input.PreviousTxIndex,
			Sequence: 1,
		},
	})

	script, err := address.ToOutputScript(receivingAddress)
	if err != nil {
		return "", err
	}

	value, err := elementsutil.ValueFromBytes(input.WitnessUtxo.Value)
	if err != nil {
		return "", err
	}

	if value-fees < 0 {
		return "", fmt.Errorf("insufficient funds")
	}

	updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  elementsutil.AssetHashFromBytes(input.WitnessUtxo.Asset),
			Amount: value - fees,
			Script: script,
		},
		{
			Asset:  elementsutil.AssetHashFromBytes(input.WitnessUtxo.Asset),
			Amount: fees,
		},
	})

}
