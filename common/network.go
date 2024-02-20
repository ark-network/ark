package common

type Network struct {
	Name   string
	SecKey string
	Addr   string
}

var MainNet = Network{
	Name: "mainnet",
	Addr: "ark",
}

var TestNet = Network{
	Name: "testnet",
	Addr: "tark",
}
