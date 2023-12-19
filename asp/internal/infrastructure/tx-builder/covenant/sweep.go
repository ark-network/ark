package txbuilder

import (
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/sirupsen/logrus"
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
			if isSweep, sequence := decodeSweepScript(leaf.Script); isSweep {
				var asNumber int64
				for i := len(sequence) - 1; i >= 0; i-- {
					asNumber = asNumber<<8 | int64(sequence[i])
				}

				lifetime, err := common.BIP68Decode(sequence)
				if err != nil {
					return nil, err
				}

				logrus.Debug("lifetime: ", lifetime)

				logrus.Debug("sequence: ", asNumber)

				if err := updater.AddInputs([]psetv2.InputArgs{input.InputArgs}); err != nil {
					return nil, err
				}

				if err := updater.AddInTapLeafScript(i, leaf); err != nil {
					return nil, err
				}

				updater.Pset.Inputs[i].Sequence = uint32(asNumber)
				break
			}
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
