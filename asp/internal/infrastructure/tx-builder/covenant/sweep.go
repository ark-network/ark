package txbuilder

import (
	"encoding/binary"
	"fmt"

	"github.com/ark-network/ark/internal/core/ports"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/psetv2"
)

func sweepTransaction(
	sweepInputs []ports.SweepInput,
	receivingAddress string,
	lbtc string,
	fees uint64,
) (*psetv2.Pset, error) {
	sweepPset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return nil, err
	}

	updater, err := psetv2.NewUpdater(sweepPset)
	if err != nil {
		return nil, err
	}

	amount := uint64(0)

	for i, input := range sweepInputs {
		if err := updater.AddInputs([]psetv2.InputArgs{input.InputArgs}); err != nil {
			return nil, err
		}

		var sweepLeaf psetv2.TapLeafScript
		for _, leaf := range input.Leaves {
			if isSweep, sequence := decodeSweepScript(leaf.Script); isSweep {
				sweepLeaf = leaf
				updater.Pset.Inputs[i].Sequence = binary.LittleEndian.Uint32(sequence)
				break
			}
		}

		if sweepLeaf.Script == nil {
			return nil, fmt.Errorf("sweep leaf not found")
		}

		if err := updater.AddInTapLeafScript(i, sweepLeaf); err != nil {
			return nil, err
		}

		amount += input.Amount
	}

	script, err := address.ToOutputScript(receivingAddress)
	if err != nil {
		return nil, err
	}

	if amount-fees < 0 {
		return nil, fmt.Errorf("insufficient funds")
	}

	updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: amount - fees,
			Script: script,
		},
		{
			Asset:  lbtc,
			Amount: fees,
		},
	})

	return sweepPset, nil
}
