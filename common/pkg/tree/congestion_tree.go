package tree

// Node is a struct embedding the transaction and the parent txid of a congestion tree node
type Node struct {
	Txid       string
	Tx         string
	ParentTxid string
	Leaf       bool
}

// CongestionTree is reprensented as a matrix of TreeNode struct
// the first level of the matrix is the root of the tree
type CongestionTree [][]Node

// Leaves returns the leaves of the congestion tree (the vtxos txs)
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

// Children returns all the nodes that have the given node as parent
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
