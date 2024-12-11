package bitcointree

import (
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func BuildForfeitTxs(
	connectorTx *psbt.Packet, vtxoInput *wire.OutPoint,
	vtxoAmount, connectorAmount, feeAmount uint64,
	vtxoScript, serverScript []byte,
	txLocktime uint32,
) (forfeitTxs []*psbt.Packet, err error) {
	version := int32(2)
	connectors, prevouts := getConnectorInputs(connectorTx, int64(connectorAmount))

	for i, connectorInput := range connectors {
		connectorPrevout := prevouts[i]

		ins := []*wire.OutPoint{connectorInput, vtxoInput}
		outs := []*wire.TxOut{{
			Value:    int64(vtxoAmount) + int64(connectorAmount) - int64(feeAmount),
			PkScript: serverScript,
		}}

		vtxoSequence := wire.MaxTxInSequenceNum
		if txLocktime != 0 {
			vtxoSequence = wire.MaxTxInSequenceNum - 1
		}

		partialTx, err := psbt.New(
			ins,
			outs,
			version,
			txLocktime,
			[]uint32{wire.MaxTxInSequenceNum, vtxoSequence},
		)
		if err != nil {
			return nil, err
		}

		updater, err := psbt.NewUpdater(partialTx)
		if err != nil {
			return nil, err
		}

		if err := updater.AddInWitnessUtxo(connectorPrevout, 0); err != nil {
			return nil, err
		}

		if err := updater.AddInWitnessUtxo(&wire.TxOut{
			Value:    int64(vtxoAmount),
			PkScript: vtxoScript,
		}, 1); err != nil {
			return nil, err
		}

		if err := updater.AddInSighashType(txscript.SigHashDefault, 1); err != nil {
			return nil, err
		}

		forfeitTxs = append(forfeitTxs, partialTx)
	}

	return forfeitTxs, nil
}

func getConnectorInputs(partialTx *psbt.Packet, connectorAmount int64) ([]*wire.OutPoint, []*wire.TxOut) {
	inputs := make([]*wire.OutPoint, 0)
	witnessUtxos := make([]*wire.TxOut, 0)

	for i, output := range partialTx.UnsignedTx.TxOut {
		if output.Value == connectorAmount {
			inputs = append(inputs, &wire.OutPoint{
				Hash:  partialTx.UnsignedTx.TxHash(),
				Index: uint32(i),
			})
			witnessUtxos = append(witnessUtxos, output)
		}
	}

	return inputs, witnessUtxos
}
