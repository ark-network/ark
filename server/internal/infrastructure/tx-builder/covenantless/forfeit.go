package txbuilder

import (
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/sirupsen/logrus"
)

func craftForfeitTxs(
	connectorTx *psbt.Packet,
	vtxo domain.Vtxo,
	vtxoForfeitTapLeaf *psbt.TaprootTapLeafScript,
	vtxoScript, aspScript []byte,
	minRelayFee uint64,
	connectorAmount int64,
) (forfeitTxs []string, err error) {
	connectors, prevouts := getConnectorInputs(connectorTx, connectorAmount)

	for i, connectorInput := range connectors {
		connectorPrevout := prevouts[i]

		vtxoHash, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return nil, err
		}

		vtxoInput := &wire.OutPoint{
			Hash:  *vtxoHash,
			Index: vtxo.VOut,
		}

		partialTx, err := psbt.New(
			[]*wire.OutPoint{connectorInput, vtxoInput},
			[]*wire.TxOut{{
				Value:    int64(vtxo.Amount) + int64(connectorAmount) - int64(minRelayFee),
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

		logrus.Debugf("vtxo %s:%d amount %d", vtxo.Txid, vtxo.VOut, vtxo.Amount)

		if err := updater.AddInWitnessUtxo(&wire.TxOut{
			Value:    int64(vtxo.Amount),
			PkScript: vtxoScript,
		}, 1); err != nil {
			return nil, err
		}

		if err := updater.AddInSighashType(txscript.SigHashDefault, 1); err != nil {
			return nil, err
		}

		updater.Upsbt.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{vtxoForfeitTapLeaf}

		tx, err := partialTx.B64Encode()
		if err != nil {
			return nil, err
		}

		forfeitTxs = append(forfeitTxs, tx)
	}
	return forfeitTxs, nil
}
