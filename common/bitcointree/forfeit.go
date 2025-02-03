package bitcointree

import (
	"math"
	"runtime"
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
	nbWorkers := int(math.Min(float64(runtime.NumCPU()), float64(len(connectors))))
	forfeitTxs := make([]*psbt.Packet, len(connectors))
	jobs := make(chan chJob, len(connectors))
	chErr := make(chan error, 1)
	chTxs := make(chan chTx, len(connectors))

	wg := sync.WaitGroup{}
	wg.Add(len(connectors))

	for i := 0; i < nbWorkers; i++ {
		go func() {
			defer wg.Done()

			for job := range jobs {
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
						chErr <- err
						return
					}

					updater, err := psbt.NewUpdater(partialTx)
					if err != nil {
						chErr <- err
						return
					}

					if err := updater.AddInWitnessUtxo(connectorPrevout, 0); err != nil {
						chErr <- err
						return
					}

					if err := updater.AddInWitnessUtxo(&wire.TxOut{
						Value:    int64(vtxoAmount),
						PkScript: vtxoScript,
					}, 1); err != nil {
						chErr <- err
						return
					}

					if err := updater.AddInSighashType(txscript.SigHashDefault, 1); err != nil {
						chErr <- err
						return
					}

					chTxs <- chTx{i, partialTx}
				}(job.i, job.connectorInput, job.connectorPrevout)
			}
		}()
	}

	for i := range connectors {
		select {
		case err := <-chErr:
			return nil, err
		default:
			connectorPrevout := prevouts[i]
			connectorInput := connectors[i]
			jobs <- chJob{i, connectorInput, connectorPrevout}
		}
	}
	close(jobs)
	wg.Wait()

	count := 0
	for {
		select {
		case err := <-chErr:
			close(chErr)
			return nil, err
		case res := <-chTxs:
			forfeitTxs[res.i] = res.tx
			count++
			if count == len(connectors) {
				close(chTxs)
				close(chErr)
				return forfeitTxs, nil
			}
		}
	}
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

type chJob struct {
	i                int
	connectorInput   *wire.OutPoint
	connectorPrevout *wire.TxOut
}

type chTx struct {
	i  int
	tx *psbt.Packet
}
