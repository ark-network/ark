package common

import (
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/input"
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
