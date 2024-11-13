package txbuilder

import (
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

func craftConnectorTx(
	input *wire.OutPoint, inputScript []byte, outputs []*wire.TxOut,
) (*psbt.Packet, error) {
	ptx, err := psbt.New(
		[]*wire.OutPoint{input},
		outputs,
		3,
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

	inputAmount := int64(0)
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
