package txbuilder

import (
	"context"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func sweepTransaction(
	wallet ports.WalletService,
	sweepInputs []ports.SweepInput,
) (*psbt.Packet, error) {
	ins := make([]*wire.OutPoint, 0)

	for _, input := range sweepInputs {
		ins = append(ins, &wire.OutPoint{
			Hash:  input.GetHash(),
			Index: input.GetIndex(),
		})
	}

	sweepPartialTx, err := psbt.New(
		ins,
		nil,
		2,
		0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
	if err != nil {
		return nil, err
	}

	updater, err := psbt.NewUpdater(sweepPartialTx)
	if err != nil {
		return nil, err
	}

	amount := int64(0)

	for i, sweepInput := range sweepInputs {
		sweepPartialTx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
			{
				ControlBlock: sweepInput.GetControlBlock(),
				Script:       sweepInput.GetLeafScript(),
				LeafVersion:  txscript.BaseLeafVersion,
			},
		}

		sweepPartialTx.Inputs[i].TaprootInternalKey = schnorr.SerializePubKey(sweepInput.GetInternalKey())

		sweepClosure := bitcointree.CSVSigClosure{}
		valid, err := sweepClosure.Decode(sweepInput.GetLeafScript())
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, fmt.Errorf("invalid csv script")
		}

		amount += int64(sweepInput.GetAmount())

		ctrlBlock, err := txscript.ParseControlBlock(sweepInput.GetControlBlock())
		if err != nil {
			return nil, err
		}

		root := ctrlBlock.RootHash(sweepInput.GetLeafScript())

		prevoutTaprootKey := txscript.ComputeTaprootOutputKey(
			sweepInput.GetInternalKey(),
			root,
		)

		script, err := taprootOutputScript(prevoutTaprootKey)
		if err != nil {
			return nil, err
		}

		prevout := &wire.TxOut{
			Value:    int64(sweepInput.GetAmount()),
			PkScript: script,
		}

		if err := updater.AddInWitnessUtxo(prevout, i); err != nil {
			return nil, err
		}

		sequence, err := common.BIP68EncodeAsNumber(sweepClosure.Seconds)
		if err != nil {
			return nil, err
		}

		sweepPartialTx.UnsignedTx.TxIn[i].Sequence = sequence
	}

	ctx := context.Background()

	sweepAddress, err := wallet.DeriveAddresses(ctx, 1)
	if err != nil {
		return nil, err
	}

	addr, err := btcutil.DecodeAddress(sweepAddress[0], nil)
	if err != nil {
		return nil, err
	}

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}

	sweepPartialTx.UnsignedTx.AddTxOut(&wire.TxOut{
		Value:    amount,
		PkScript: script,
	})
	sweepPartialTx.Outputs = append(sweepPartialTx.Outputs, psbt.POutput{})

	b64, err := sweepPartialTx.B64Encode()
	if err != nil {
		return nil, err
	}

	fees, err := wallet.EstimateFees(ctx, b64)
	if err != nil {
		return nil, err
	}

	if amount < int64(fees) {
		return nil, fmt.Errorf("insufficient funds (%d) to cover fees (%d) for sweep transaction", amount, fees)
	}

	sweepPartialTx.UnsignedTx.TxOut[0].Value = amount - int64(fees)

	return sweepPartialTx, nil
}
