package bitcointree

import (
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func BuildForfeitTx(
	connectorInput, vtxoInput *wire.OutPoint,
	vtxoAmount, connectorAmount, feeAmount uint64,
	vtxoScript, connectorScript, serverScript []byte,
	txLocktime uint32,
) (*psbt.Packet, error) {
	version := int32(2)

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

	connectorPrevout := wire.NewTxOut(int64(connectorAmount), connectorScript)
	if err := updater.AddInWitnessUtxo(connectorPrevout, 0); err != nil {
		return nil, err
	}

	vtxoPrevout := wire.NewTxOut(int64(vtxoAmount), vtxoScript)
	if err := updater.AddInWitnessUtxo(vtxoPrevout, 1); err != nil {
		return nil, err
	}

	if err := updater.AddInSighashType(txscript.SigHashDefault, 0); err != nil {
		return nil, err
	}

	if err := updater.AddInSighashType(txscript.SigHashDefault, 1); err != nil {
		return nil, err
	}

	return partialTx, nil
}
