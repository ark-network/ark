package bitcointree

import (
	"sync"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func BuildForfeitTxs(
	connectorTx *psbt.Packet, vtxoInput *wire.OutPoint,
	vtxoAmount, connectorAmount, feeAmount uint64,
	vtxoScript, serverScript []byte,
	txLocktime uint32,
) ([]*psbt.Packet, error) {
	version := int32(2)
	connectors, prevouts := getConnectorInputs(connectorTx, int64(connectorAmount))
	forfeitTxs := make([]*psbt.Packet, len(connectors))
	chTxs := make(chan chTx, len(connectors))

	wg := &sync.WaitGroup{}
	wg.Add(len(connectors))
	go func() {
		wg.Wait()
		close(chTxs)
	}()

	for i := range connectors {
		connectorPrevout := prevouts[i]
		connectorInput := connectors[i]

		go func(i int, connectorInput *wire.OutPoint, connectorPrevout *wire.TxOut) {
			defer wg.Done()

			ins := []*wire.OutPoint{connectorInput, vtxoInput}
			outs := []*wire.TxOut{{
				Value:    int64(vtxoAmount) + int64(connectorAmount) - int64(feeAmount),
				PkScript: serverScript,
			}}

			vtxoSequence := wire.MaxTxInSequenceNum
			if txLocktime != 0 {
				vtxoSequence = wire.MaxTxInSequenceNum - 1
			}
			txSequence := []uint32{wire.MaxTxInSequenceNum, vtxoSequence}

			partialTx, err := psbt.New(
				ins, outs, version, txLocktime, txSequence,
			)
			if err != nil {
				chTxs <- chTx{-1, nil, err}
				return
			}

			updater, err := psbt.NewUpdater(partialTx)
			if err != nil {
				chTxs <- chTx{-1, nil, err}
				return
			}

			if err := updater.AddInWitnessUtxo(connectorPrevout, 0); err != nil {
				chTxs <- chTx{-1, nil, err}
				return
			}

			if err := updater.AddInWitnessUtxo(&wire.TxOut{
				Value:    int64(vtxoAmount),
				PkScript: vtxoScript,
			}, 1); err != nil {
				chTxs <- chTx{-1, nil, err}
				return
			}

			if err := updater.AddInSighashType(txscript.SigHashDefault, 1); err != nil {
				chTxs <- chTx{-1, nil, err}
				return
			}

			chTxs <- chTx{i, partialTx, nil}
		}(i, connectorInput, connectorPrevout)
	}

	for c := range chTxs {
		if c.err != nil {
			return nil, c.err
		}
		forfeitTxs[c.i] = c.tx
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

type chTx struct {
	i   int
	tx  *psbt.Packet
	err error
}
