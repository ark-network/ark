package txbuilder

import (
	"context"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
	"github.com/vulpemventures/go-elements/transaction"
)

func sweepTransaction(
	wallet ports.WalletService,
	sweepInputs []ports.SweepInput,
	lbtc string,
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
		leaf := input.SweepLeaf
		isSweep, _, lifetime, err := tree.DecodeSweepScript(leaf.Script)
		if err != nil {
			return nil, err
		}

		if isSweep {
			amount += input.Amount

			if err := updater.AddInputs([]psetv2.InputArgs{input.InputArgs}); err != nil {
				return nil, err
			}

			if err := updater.AddInTapLeafScript(i, leaf); err != nil {
				return nil, err
			}

			assetHash, err := elementsutil.AssetHashToBytes(lbtc)
			if err != nil {
				return nil, err
			}

			value, err := elementsutil.ValueToBytes(input.Amount)
			if err != nil {
				return nil, err
			}

			root := leaf.ControlBlock.RootHash(leaf.Script)
			taprootKey := taproot.ComputeTaprootOutputKey(leaf.ControlBlock.InternalKey, root)
			script, err := taprootOutputScript(taprootKey)
			if err != nil {
				return nil, err
			}

			witnessUtxo := &transaction.TxOutput{
				Asset:  assetHash,
				Value:  value,
				Script: script,
				Nonce:  emptyNonce,
			}

			if err := updater.AddInWitnessUtxo(i, witnessUtxo); err != nil {
				return nil, err
			}

			sequence, err := common.BIP68EncodeAsNumber(lifetime)
			if err != nil {
				return nil, err
			}

			updater.Pset.Inputs[i].Sequence = sequence
			continue
		}

		return nil, fmt.Errorf("invalid sweep script")
	}

	ctx := context.Background()

	sweepAddress, err := wallet.DeriveAddresses(ctx, 1)
	if err != nil {
		return nil, err
	}

	script, err := address.ToOutputScript(sweepAddress[0])
	if err != nil {
		return nil, err
	}

	if err := updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: amount,
			Script: script,
		},
	}); err != nil {
		return nil, err
	}

	b64, err := sweepPset.ToBase64()
	if err != nil {
		return nil, err
	}

	fees, err := wallet.EstimateFees(ctx, b64)
	if err != nil {
		return nil, err
	}

	if amount < fees {
		return nil, fmt.Errorf("insufficient funds (%d) to cover fees (%d) for sweep transaction", amount, fees)
	}

	updater.Pset.Outputs[0].Value = amount - fees

	if err := updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: fees,
		},
	}); err != nil {
		return nil, err
	}

	return sweepPset, nil
}
