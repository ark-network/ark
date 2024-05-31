package txbuilder

import (
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

func craftConnectorTx(
	input *wire.OutPoint, inputScript []byte, outputs []*wire.TxOut, feeAmount uint64,
) (*psbt.Packet, error) {
	ptx, err := psbt.New(
		[]*wire.OutPoint{input},
		outputs,
		2,
		0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
	if err != nil {
		return nil, err
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return nil, err
	}

	inputAmount := int64(feeAmount)
	for _, output := range outputs {
		inputAmount += output.Value
	}

	if err := updater.AddInWitnessUtxo(&wire.TxOut{
		Value:    inputAmount,
		PkScript: inputScript,
	}, 0); err != nil {
		return nil, err
	}

	return ptx, nil
}

func getConnectorInputs(partialTx *psbt.Packet) ([]*wire.OutPoint, []*wire.TxOut) {
	inputs := make([]*wire.OutPoint, 0)
	witnessUtxos := make([]*wire.TxOut, 0)

	for i, output := range partialTx.UnsignedTx.TxOut {
		if output.Value == int64(connectorAmount) {
			inputs = append(inputs, &wire.OutPoint{
				Hash:  partialTx.UnsignedTx.TxHash(),
				Index: uint32(i),
			})
			witnessUtxos = append(witnessUtxos, output)
		}
	}

	return inputs, witnessUtxos
}
