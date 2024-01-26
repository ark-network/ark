package txbuilder

import (
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
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
		for _, leaf := range input.Leaves {
			isSweep, _, lifetime, err := tree.DecodeSweepScript(leaf.Script)
			if err != nil {
				return nil, err
			}

			if isSweep {
				if err := updater.AddInputs([]psetv2.InputArgs{input.InputArgs}); err != nil {
					return nil, err
				}

				if err := updater.AddInTapLeafScript(i, leaf); err != nil {
					return nil, err
				}

				sequence, err := common.BIP68EncodeAsNumber(lifetime)
				if err != nil {
					return nil, err
				}

				updater.Pset.Inputs[i].Sequence = sequence
				break
			}
		}

		amount += input.Amount
	}

	script, err := address.ToOutputScript(receivingAddress)
	if err != nil {
		return nil, err
	}

	if amount < fees {
		return nil, fmt.Errorf("insufficient funds to cover fees for sweep transaction")
	}

	if err := updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: amount - fees,
			Script: script,
		},
		{
			Asset:  lbtc,
			Amount: fees,
		},
	}); err != nil {
		return nil, err
	}

	return sweepPset, nil
}
