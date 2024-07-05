package covenant

import (
	"github.com/ark-network/ark/common"
	"github.com/vulpemventures/go-elements/network"
)

func toElementsNetwork(net *common.Network) network.Network {
	switch net.Name {
	case common.Liquid.Name:
		return network.Liquid
	case common.LiquidTestNet.Name:
		return network.Testnet
	case common.LiquidRegTest.Name:
		return network.Regtest
	default:
		return network.Liquid
	}
}
