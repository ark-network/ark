package txbuilder

import (
	"context"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightningnetwork/lnd/input"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
	"github.com/vulpemventures/go-elements/transaction"
)

func (b *txBuilder) craftForfeitTxs(
	connectorTx *psetv2.Pset,
	connectorAmount uint64,
	vtxo domain.Vtxo,
	vtxoForfeitTapleaf taproot.TapscriptElementsProof,
	vtxoScript, aspScript []byte,
) (forfeitTxs []string, err error) {
	connectors, prevouts := getConnectorInputs(connectorTx, connectorAmount)

	for i, connectorInput := range connectors {
		weightEstimator := &input.TxWeightEstimator{}

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

		vtxoInput := psetv2.InputArgs{
			Txid:    vtxo.Txid,
			TxIndex: vtxo.VOut,
		}

		vtxoAmount, _ := elementsutil.ValueToBytes(vtxo.Amount)

		if err := updater.AddInputs([]psetv2.InputArgs{connectorInput, vtxoInput}); err != nil {
			return nil, err
		}

		if err = updater.AddInWitnessUtxo(0, connectorPrevout); err != nil {
			return nil, err
		}

		if err := updater.AddInSighashType(0, txscript.SigHashAll); err != nil {
			return nil, err
		}

		weightEstimator.AddP2WKHInput()

		vtxoPrevout := transaction.NewTxOutput(connectorPrevout.Asset, vtxoAmount, vtxoScript)

		if err = updater.AddInWitnessUtxo(1, vtxoPrevout); err != nil {
			return nil, err
		}

		if err := updater.AddInSighashType(1, txscript.SigHashDefault); err != nil {
			return nil, err
		}

		unspendableKey := tree.UnspendableKey()

		tapScript := psetv2.NewTapLeafScript(vtxoForfeitTapleaf, unspendableKey)
		if err := updater.AddInTapLeafScript(1, tapScript); err != nil {
			return nil, err
		}

		weightEstimator.AddTapscriptInput(64*2, &waddrmgr.Tapscript{
			ControlBlock:   &tapScript.ControlBlock.ControlBlock,
			RevealedScript: tapScript.TapLeaf.Script,
		})

		connectorAmount, err := elementsutil.ValueFromBytes(connectorPrevout.Value)
		if err != nil {
			return nil, err
		}

		weightEstimator.AddP2WKHOutput()
		weightEstimator.AddP2WKHOutput()

		feeAmount, err := b.wallet.MinRelayFee(context.Background(), uint64(weightEstimator.VSize()))
		if err != nil {
			return nil, err
		}

		err = updater.AddOutputs([]psetv2.OutputArgs{
			{
				Asset:  asset,
				Amount: vtxo.Amount + connectorAmount - feeAmount,
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

		tx, err := pset.ToBase64()
		if err != nil {
			return nil, err
		}

		forfeitTxs = append(forfeitTxs, tx)
	}
	return forfeitTxs, nil
}
