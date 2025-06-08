package common

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

type VtxoInput struct {
	Outpoint           *wire.OutPoint
	Amount             int64
	Tapscript          *waddrmgr.Tapscript
	WitnessSize        int
	RevealedTapscripts []string
	ArkScript          []byte
}
