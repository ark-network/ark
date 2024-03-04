package common

type Network struct {
	Name string
	Addr string
}

var MainNet = Network{
	Name: "mainnet",
	Addr: "ark",
}

var TestNet = Network{
	Name: "testnet",
	Addr: "tark",
}

var RegTest = Network{
	Name: "regtest",
	Addr: TestNet.Addr,
}
