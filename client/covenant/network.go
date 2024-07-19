package covenant

import (
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/vulpemventures/go-elements/network"
)

func toElementsNetworkFromName(name string) network.Network {
	switch name {
	case common.Liquid.Name:
		return network.Liquid
	case common.LiquidTestNet.Name:
		return network.Testnet
	case common.LiquidRegTest.Name:
		return network.Regtest
	default:
		fmt.Printf("unknown network")
		return network.Liquid
	}
}

func toElementsNetwork(net *common.Network) network.Network {
	return toElementsNetworkFromName(net.Name)
}
