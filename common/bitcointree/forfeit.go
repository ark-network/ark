package bitcointree

import (
	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func BuildForfeitTxs(
	connectorTx *psbt.Packet,
	vtxoInput *wire.OutPoint,
	vtxoAmount,
	connectorAmount,
	feeAmount uint64,
	vtxoScript []byte,
	aspPubKey *secp256k1.PublicKey,
) (forfeitTxs []*psbt.Packet, err error) {
	aspScript, err := common.P2TRScript(aspPubKey)
	if err != nil {
		return nil, err
	}

	connectors, prevouts := getConnectorInputs(connectorTx, int64(connectorAmount))

	for i, connectorInput := range connectors {
		connectorPrevout := prevouts[i]

		partialTx, err := psbt.New(
			[]*wire.OutPoint{connectorInput, vtxoInput},
			[]*wire.TxOut{{
				Value:    int64(vtxoAmount) + int64(connectorAmount) - int64(feeAmount),
				PkScript: aspScript,
			}},
			2,
			0,
			[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
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
