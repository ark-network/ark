package txbuilder

import (
	"context"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/ports"
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
		sweepClosure := &tree.CSVSigClosure{}
		isSweep, err := sweepClosure.Decode(input.GetLeafScript())
		if err != nil {
			return nil, err
		}

		if !isSweep {
			return nil, fmt.Errorf("invalid sweep script")
		}

		amount += input.GetAmount()

		if err := updater.AddInputs([]psetv2.InputArgs{
			{
				Txid:    input.GetHash().String(),
				TxIndex: input.GetIndex(),
			},
		}); err != nil {
			return nil, err
		}

		ctrlBlock, err := taproot.ParseControlBlock(input.GetControlBlock())
		if err != nil {
			return nil, err
		}

		leaf := psetv2.TapLeafScript{
			TapElementsLeaf: taproot.NewBaseTapElementsLeaf(input.GetLeafScript()),
			ControlBlock:    *ctrlBlock,
		}

		if err := updater.AddInTapLeafScript(i, leaf); err != nil {
			return nil, err
		}

		assetHash, err := elementsutil.AssetHashToBytes(lbtc)
		if err != nil {
			return nil, err
		}

		value, err := elementsutil.ValueToBytes(input.GetAmount())
		if err != nil {
			return nil, err
		}

		root := leaf.ControlBlock.RootHash(leaf.Script)
		taprootKey := taproot.ComputeTaprootOutputKey(leaf.ControlBlock.InternalKey, root)
		script, err := common.P2TRScript(taprootKey)
		if err != nil {
			return nil, err
		}

		witnessUtxo := transaction.NewTxOutput(assetHash, value, script)

		if err := updater.AddInWitnessUtxo(i, witnessUtxo); err != nil {
			return nil, err
		}

		sequence, err := common.BIP68Sequence(sweepClosure.Seconds)
		if err != nil {
			return nil, err
		}

		updater.Pset.Inputs[i].Sequence = sequence
		continue
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
