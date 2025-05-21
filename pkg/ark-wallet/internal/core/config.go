package application

import (
	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/chaincfg"
)

type WalletConfig struct {
	Datadir string
	Network common.Network
}

func (c WalletConfig) chainParams() *chaincfg.Params {
	switch c.Network.Name {
	case common.Bitcoin.Name:
		return &chaincfg.MainNetParams
	//case common.BitcoinTestNet4.Name: //TODO uncomment once supported
	//	return &chaincfg.TestNet4Params
	case common.BitcoinTestNet.Name:
		return &chaincfg.TestNet3Params
	case common.BitcoinSigNet.Name:
		return &chaincfg.SigNetParams
	case common.BitcoinMutinyNet.Name:
		return &common.MutinyNetSigNetParams
	case common.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
	default:
		return &chaincfg.MainNetParams
	}
}
