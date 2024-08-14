package common

import "strings"

type Network struct {
	Name string
	Addr string
}

var Liquid = Network{
	Name: "liquid",
	Addr: "ark",
}

var LiquidTestNet = Network{
	Name: "liquidtestnet",
	Addr: "tark",
}

var LiquidRegTest = Network{
	Name: "liquidregtest",
	Addr: LiquidTestNet.Addr,
}

var Bitcoin = Network{
	Name: "bitcoin",
	Addr: "ark",
}

var BitcoinTestNet = Network{
	Name: "testnet",
	Addr: "tark",
}

var BitcoinRegTest = Network{
	Name: "regtest",
	Addr: BitcoinTestNet.Addr,
}

var BitcoinSigNet = Network{
	Name: "signet",
	Addr: BitcoinTestNet.Addr,
}

func IsLiquid(network Network) bool {
	return strings.Contains(network.Name, "liquid")
}
