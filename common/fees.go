package common

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

var TreeTxSize = (&input.TxWeightEstimator{}).
	AddTaprootKeySpendInput(txscript.SigHashDefault). // parent
	AddP2TROutput().                                  // left child
	AddP2TROutput().                                  // right child
	VSize()

// liquid node size is 2x the bitcoin node size (avoid min-relay-fee issues with the low fee rate on liquid)
var CovenantTreeTxSize = TreeTxSize * 2

var ConnectorTxSize = (&input.TxWeightEstimator{}).
	AddTaprootKeySpendInput(txscript.SigHashDefault).
	AddP2TROutput().
	AddP2TROutput().
	VSize()

func ComputeForfeitTxFee(
	feeRate chainfee.SatPerKVByte,
	tapscript *waddrmgr.Tapscript,
	witnessSize int,
	serverScriptClass txscript.ScriptClass,
) (uint64, error) {
	txWeightEstimator := &input.TxWeightEstimator{}

	txWeightEstimator.AddTaprootKeySpendInput(txscript.SigHashDefault) // connector input
	txWeightEstimator.AddTapscriptInput(
		lntypes.WeightUnit(witnessSize),
		tapscript,
	)

	switch serverScriptClass {
	case txscript.PubKeyHashTy:
		txWeightEstimator.AddP2PKHOutput()
	case txscript.ScriptHashTy:
		txWeightEstimator.AddP2SHOutput()
	case txscript.WitnessV0PubKeyHashTy:
		txWeightEstimator.AddP2WKHOutput()
	case txscript.WitnessV0ScriptHashTy:
		txWeightEstimator.AddP2WSHOutput()
	case txscript.WitnessV1TaprootTy:
		txWeightEstimator.AddP2TROutput()
	default:
		return 0, fmt.Errorf("unknown server script class: %v", serverScriptClass)
	}

	return uint64(feeRate.FeeForVSize(lntypes.VByte(txWeightEstimator.VSize())).ToUnit(btcutil.AmountSatoshi)), nil
}

func ComputeRedeemTxFee(
	feeRate chainfee.SatPerKVByte,
	vtxos []VtxoInput,
	numOutputs int,
) (int64, error) {
	if len(vtxos) <= 0 {
		return 0, fmt.Errorf("missing vtxos")
	}

	redeemTxWeightEstimator := &input.TxWeightEstimator{}

	// Estimate inputs
	for _, vtxo := range vtxos {
		if vtxo.Tapscript == nil {
			txid := vtxo.Outpoint.Hash.String()
			return 0, fmt.Errorf("missing tapscript for vtxo %s", txid)
		}

		redeemTxWeightEstimator.AddTapscriptInput(lntypes.WeightUnit(vtxo.WitnessSize), vtxo.Tapscript)
	}

	// Estimate outputs
	for i := 0; i < numOutputs; i++ {
		redeemTxWeightEstimator.AddP2TROutput()
	}

	return int64(feeRate.FeeForVSize(lntypes.VByte(redeemTxWeightEstimator.VSize())).ToUnit(btcutil.AmountSatoshi)), nil
}
