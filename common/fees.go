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

var ConnectorTxSize = (&input.TxWeightEstimator{}).
	AddP2WKHInput().
	AddP2WKHOutput().
	AddP2WKHOutput().
	VSize()
