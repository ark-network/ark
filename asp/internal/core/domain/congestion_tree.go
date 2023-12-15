package domain

type Node struct {
	Txid       string
	Tx         string
	ParentTxid string
	Leaf       bool
}

type CongestionTree [][]Node

func (c CongestionTree) Root() Node {
	return c[0][0]
}

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

func (c CongestionTree) Children(nodeTxid string) []Node {
	var children []Node
	for _, level := range c {
		for _, node := range level {
			if node.ParentTxid == nodeTxid {
				children = append(children, node)
			}
		}
	}

	return children
}

func (c CongestionTree) NumberOfNodes() int {
	var count int
	for _, level := range c {
		count += len(level)
	}
	return count
}
