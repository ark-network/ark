package covenantless

import (
	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/chaincfg"
)

func toChainParams(net *common.Network) chaincfg.Params {
	// we pass nil to have the equivalent of dnssec=0 in bitcoin.conf
	mutinyNetSigNetParams := chaincfg.CustomSignetParams(common.MutinyNetChallenge, nil)
	mutinyNetSigNetParams.TargetTimePerBlock = common.MutinyNetBlockTime
	switch net.Name {
	case common.Bitcoin.Name:
		return chaincfg.MainNetParams
	case common.BitcoinTestNet.Name:
		return chaincfg.TestNet3Params
	case common.BitcoinRegTest.Name:
		return chaincfg.RegressionNetParams
	case common.BitcoinSigNet.Name:
		return mutinyNetSigNetParams
	default:
		return chaincfg.MainNetParams
	}
}
