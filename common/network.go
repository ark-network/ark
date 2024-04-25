package common

type Network struct {
	Name string
	Addr string
}

var Liquid = Network{
	Name: "liquid",
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
