package tree

import (
	"errors"
)

// Node is a struct embedding the transaction and the parent txid of a congestion tree node
type Node struct {
	Txid       string
	Tx         string
	ParentTxid string
	Leaf       bool
}

var (
	ErrParentNotFound = errors.New("parent not found")
	ErrLeafNotFound   = errors.New("leaf not found in congestion tree")
)

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

// FindLeaves returns all the leaves that are reachable from the given node txid
func (c CongestionTree) FindLeaves(fromtxid string) ([]Node, error) {
	allLeaves := c.Leaves()
	foundLeaves := make([]Node, 0)

	for _, leaf := range allLeaves {
		branch, err := c.Branch(leaf.Txid)
		if err != nil {
			return nil, err
		}

		for _, node := range branch {
			if node.ParentTxid == fromtxid {
				foundLeaves = append(foundLeaves, leaf)
				break
			}
		}
	}

	return foundLeaves, nil
}

func (c CongestionTree) NumberOfNodes() int {
	var count int
	for _, level := range c {
		count += len(level)
	}
	return count
}

func (c CongestionTree) Branch(vtxoTxid string) ([]Node, error) {
	branch := make([]Node, 0)

	leaves := c.Leaves()
	// check if the vtxo is a leaf
	found := false
	for _, leaf := range leaves {
		if leaf.Txid == vtxoTxid {
			found = true
			branch = append(branch, leaf)
			break
		}
	}
	if !found {
		return nil, ErrLeafNotFound
	}

	rootTxid := c[0][0].Txid

	for branch[0].Txid != rootTxid {
		parent, err := branch[0].findParent(c)
		if err != nil {
			return nil, err
		}
		branch = append([]Node{parent}, branch...)
	}

	return branch, nil
}

func (n Node) findParent(tree CongestionTree) (Node, error) {
	for _, level := range tree {
		for _, node := range level {
			if node.Txid == n.ParentTxid {
				return node, nil
			}
		}
	}
	return Node{}, ErrParentNotFound
}
