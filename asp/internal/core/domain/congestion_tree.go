package domain

type Node struct {
	Txid       string
	Tx         string
	ParentTxid string
	Leaf       bool
}

type CongestionTree [][]Node

func (c CongestionTree) Leaves() []Node {
	leaves := c[len(c)-1]
	for _, level := range c[:len(c)-1] {
		for _, node := range level {
			if node.Leaf {
				leaves = append(leaves, node)
			}
		}
	}

	return leaves
}

func (c CongestionTree) NumberOfNodes() int {
	var count int
	for _, level := range c {
		count += len(level)
	}
	return count
}
