package domain

type Node struct {
	Txid       string
	Pset       string
	ParentTxid string
}

type CongestionTree [][]Node

func (c CongestionTree) Leaves() []Node {
	length := len(c)
	if length == 0 {
		return nil
	}

	return c[length-1]
}
