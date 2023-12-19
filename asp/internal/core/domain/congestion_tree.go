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

func (c CongestionTree) SubTree(newRootTxid string) CongestionTree {
	var newRoot Node
	found := false
	levelIndex := 0

	for index, level := range c {
		for _, node := range level {
			if node.Txid == newRootTxid {
				newRoot = Node{
					Txid: node.Txid,
					Tx:   node.Tx,
					Leaf: node.Leaf,
				}

				if newRoot.Leaf {
					return [][]Node{{newRoot}}
				}

				levelIndex = index
				found = true
				break
			}
		}

		if found {
			break
		}
	}

	if !found {
		return nil
	}

	subTree := CongestionTree{[]Node{newRoot}}

	for i := levelIndex + 1; i < len(c); i++ {
		children := make([]Node, 0)

		for _, node := range subTree[len(subTree)-1] {
			if node.Leaf {
				continue
			}

			children = append(children, c.Children(node.Txid)...)
		}

		if len(children) == 0 {
			break
		}
		subTree = append(subTree, children)
	}

	return subTree
}
