package covenantless

import (
	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/chaincfg"
)

func toChainParams(net *common.Network) chaincfg.Params {
	switch net.Name {
	case common.Bitcoin.Name:
		return chaincfg.MainNetParams
	case common.BitcoinTestNet.Name:
		return chaincfg.TestNet3Params
	case common.BitcoinRegTest.Name:
		return chaincfg.RegressionNetParams
	default:
		return chaincfg.MainNetParams
	}
}
