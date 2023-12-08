package domain

type Node struct {
	Txid       string
	Tx         string
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

func (c CongestionTree) NumberOfNodes() int {
	var count int
	for _, level := range c {
		count += len(level)
	}
	return count
}
