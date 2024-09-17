package tree

import (
	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

func MakeForfeitTxs(
	connectorTx *psetv2.Pset,
	vtxoInput psetv2.InputArgs,
	vtxoAmount,
	connectorAmount,
	feeAmount uint64,
	vtxoScript []byte,
	aspPubKey *secp256k1.PublicKey,
) (forfeitTxs []*psetv2.Pset, err error) {
	connectors, prevouts := getConnectorInputs(connectorTx, connectorAmount)

	for i, connectorInput := range connectors {
		connectorPrevout := prevouts[i]
		asset := elementsutil.AssetHashFromBytes(connectorPrevout.Asset)

		pset, err := psetv2.New(nil, nil, nil)
		if err != nil {
			return nil, err
		}

		updater, err := psetv2.NewUpdater(pset)
		if err != nil {
			return nil, err
		}

		if err := updater.AddInputs([]psetv2.InputArgs{connectorInput, vtxoInput}); err != nil {
			return nil, err
		}

		if err = updater.AddInWitnessUtxo(0, connectorPrevout); err != nil {
			return nil, err
		}

		if err := updater.AddInSighashType(0, txscript.SigHashAll); err != nil {
			return nil, err
		}

		amountBytes, err := elementsutil.ValueToBytes(vtxoAmount)
		if err != nil {
			return nil, err
		}

		vtxoPrevout := transaction.NewTxOutput(connectorPrevout.Asset, amountBytes, vtxoScript)

		if err = updater.AddInWitnessUtxo(1, vtxoPrevout); err != nil {
			return nil, err
		}

		if err := updater.AddInSighashType(1, txscript.SigHashDefault); err != nil {
			return nil, err
		}

		aspScript, err := common.P2TRScript(aspPubKey)
		if err != nil {
			return nil, err
		}

		err = updater.AddOutputs([]psetv2.OutputArgs{
			{
				Asset:  asset,
				Amount: vtxoAmount + connectorAmount - feeAmount,
				Script: aspScript,
			},
			{
				Asset:  asset,
				Amount: feeAmount,
			},
		})
		if err != nil {
			return nil, err
		}

		forfeitTxs = append(forfeitTxs, pset)
	}
	return forfeitTxs, nil
}

func getConnectorInputs(pset *psetv2.Pset, connectorAmount uint64) ([]psetv2.InputArgs, []*transaction.TxOutput) {
	txID, _ := getPsetId(pset)

	inputs := make([]psetv2.InputArgs, 0, len(pset.Outputs))
	witnessUtxos := make([]*transaction.TxOutput, 0, len(pset.Outputs))

	for i, output := range pset.Outputs {
		utx, _ := pset.UnsignedTx()

		if output.Value == connectorAmount && len(output.Script) > 0 {
			inputs = append(inputs, psetv2.InputArgs{
				Txid:    txID,
				TxIndex: uint32(i),
			})
			witnessUtxos = append(witnessUtxos, utx.Outputs[i])
		}
	}

	return inputs, witnessUtxos
}
