package tree

import (
	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

func BuildForfeitTx(
	asset string,
	connectorInput,
	vtxoInput psetv2.InputArgs,
	vtxoAmount, connectorAmount, feeAmount uint64,
	vtxoScript, connectorScript, serverScript []byte,
) (*psetv2.Pset, error) {
	var nLocktime *uint32
	if vtxoInput.TimeLock != 0 {
		nLocktime = &vtxoInput.TimeLock
	}

	pset, err := psetv2.New(nil, nil, nLocktime)
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

	assetBytes, err := elementsutil.AssetHashToBytes(asset)
	if err != nil {
		return nil, err
	}

	connectorAmountBytes, err := elementsutil.ValueToBytes(connectorAmount)
	if err != nil {
		return nil, err
	}

	connectorPrevout := transaction.NewTxOutput(assetBytes, connectorAmountBytes, connectorScript)

	if err = updater.AddInWitnessUtxo(0, connectorPrevout); err != nil {
		return nil, err
	}

	if err := updater.AddInSighashType(0, txscript.SigHashDefault); err != nil {
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

	err = updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  asset,
			Amount: vtxoAmount + connectorAmount - feeAmount,
			Script: serverScript,
		},
		{
			Asset:  asset,
			Amount: feeAmount,
		},
	})
	if err != nil {
		return nil, err
	}

	return pset, nil
}
