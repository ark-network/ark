package common

import (
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
	AddP2WKHInput().
	AddP2WKHOutput().
	AddP2WKHOutput().
	VSize()

func ComputeForfeitMinRelayFee(feeRate chainfee.SatPerKVByte, vtxoScriptTapTree TaprootTree) (uint64, error) {
	txWeightEstimator := &input.TxWeightEstimator{}

	biggestVtxoLeafProof, err := BiggestLeafMerkleProof(vtxoScriptTapTree)
	if err != nil {
		return 0, err
	}

	ctrlBlock, err := txscript.ParseControlBlock(biggestVtxoLeafProof.ControlBlock)
	if err != nil {
		return 0, err
	}

	txWeightEstimator.AddP2PKHInput() // connector input
	txWeightEstimator.AddTapscriptInput(
		64*2, // forfeit witness = 2 signatures
		&waddrmgr.Tapscript{
			RevealedScript: biggestVtxoLeafProof.Script,
			ControlBlock:   ctrlBlock,
		},
	)
	txWeightEstimator.AddP2TROutput() // asp output

	return uint64(feeRate.FeeForVSize(lntypes.VByte(txWeightEstimator.VSize())).ToUnit(btcutil.AmountSatoshi)), nil
}
