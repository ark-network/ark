package common

type Network struct {
	Name     string
	SecKey   string
	PubKey   string
	RelayKey string
	Addr     string
}

var MainNet = Network{
	Name:     "mainnet",
	SecKey:   "asec",
	PubKey:   "apub",
	RelayKey: "arelay",
	Addr:     "ark",
}

var TestNet = Network{
	Name:     "testnet",
	SecKey:   "tasec",
	PubKey:   "tapub",
	RelayKey: "tarelay",
	Addr:     "tark",
}
