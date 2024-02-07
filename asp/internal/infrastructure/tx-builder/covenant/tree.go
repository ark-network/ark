package txbuilder

import (
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
)

const (
	expirationTime = 60 * 60 * 24 * 14 // 14 days in seconds
)

type treeFactory func(outpoint psetv2.InputArgs) (tree.CongestionTree, error)

type node struct {
	sweepKey  *secp256k1.PublicKey
	receivers []domain.Receiver
	left      *node
	right     *node
	asset     string
	feeSats   uint64

	_inputTaprootKey  *secp256k1.PublicKey
	_inputTaprootTree *taproot.IndexedElementsTapScriptTree
}

func (n *node) isLeaf() bool {
	return len(n.receivers) == 1
}

func (n *node) countChildren() int {
	result := 0

	if n.left != nil {
		result++
		result += n.left.countChildren()
	}

	if n.right != nil {
		result++
		result += n.right.countChildren()
	}

	return result
}

func (n *node) inputAmount() uint64 {
	return n.outputAmount() + n.feeSats
}

func (n *node) outputAmount() uint64 {
	var amount uint64
	for _, r := range n.receivers {
		amount += r.Amount
	}

	if n.isLeaf() {
		return amount
	}

	nb := uint64(n.countChildren())

	return amount + nb*n.feeSats

}

// compute the taproot key locking the parent output of the node
func (n *node) witness() (*secp256k1.PublicKey, *taproot.IndexedElementsTapScriptTree, error) {
	if n._inputTaprootKey != nil && n._inputTaprootTree != nil {
		return n._inputTaprootKey, n._inputTaprootTree, nil
	}

	sweepClosure, err := tree.SweepScript(n.sweepKey, expirationTime)
	if err != nil {
		return nil, nil, err
	}

	if n.isLeaf() {
		taprootKey, _, err := n.vtxoWitness()
		if err != nil {
			return nil, nil, err
		}

		branchTaprootScript := tree.BranchScript(
			taprootKey, nil, n.outputAmount(), 0,
		)

		branchTaprootTree := taproot.AssembleTaprootScriptTree(branchTaprootScript, *sweepClosure)
		root := branchTaprootTree.RootNode.TapHash()

		inputTapkey := taproot.ComputeTaprootOutputKey(
			tree.UnspendableKey(),
			root[:],
		)

		n._inputTaprootKey = inputTapkey
		n._inputTaprootTree = branchTaprootTree

		return inputTapkey, branchTaprootTree, nil
	}

	leftKey, _, err := n.left.witness()
	if err != nil {
		return nil, nil, err
	}

	rightKey, _, err := n.right.witness()
	if err != nil {
		return nil, nil, err
	}

	branchTaprootLeaf := tree.BranchScript(
		leftKey, rightKey, n.left.inputAmount(), n.right.inputAmount(),
	)

	branchTaprootTree := taproot.AssembleTaprootScriptTree(branchTaprootLeaf, *sweepClosure)
	root := branchTaprootTree.RootNode.TapHash()

	taprootKey := taproot.ComputeTaprootOutputKey(
		tree.UnspendableKey(),
		root[:],
	)

	n._inputTaprootKey = taprootKey
	n._inputTaprootTree = branchTaprootTree

	return taprootKey, branchTaprootTree, nil
}

func (n *node) vtxoWitness() (*secp256k1.PublicKey, *taproot.IndexedElementsTapScriptTree, error) {
	if !n.isLeaf() {
		return nil, nil, fmt.Errorf("cannot call vtxoWitness on a non-leaf node")
	}

	sweepClosure, err := tree.SweepScript(n.sweepKey, expirationTime)
	if err != nil {
		return nil, nil, err
	}

	key, err := hex.DecodeString(n.receivers[0].Pubkey)
	if err != nil {
		return nil, nil, err
	}

	pubkey, err := secp256k1.ParsePubKey(key)
	if err != nil {
		return nil, nil, err
	}

	vtxoLeaf, err := tree.VtxoScript(pubkey)
	if err != nil {
		return nil, nil, err
	}

	// TODO: add forfeit path
	leafTaprootTree := taproot.AssembleTaprootScriptTree(*vtxoLeaf, *sweepClosure)
	root := leafTaprootTree.RootNode.TapHash()

	taprootKey := taproot.ComputeTaprootOutputKey(
		tree.UnspendableKey(),
		root[:],
	)

	return taprootKey, leafTaprootTree, nil
}

func (n *node) outputs() ([]psetv2.OutputArgs, error) {
	if n.isLeaf() {
		taprootKey, _, err := n.vtxoWitness()
		if err != nil {
			return nil, err
		}

		script, err := taprootOutputScript(taprootKey)
		if err != nil {
			return nil, err
		}

		output := &psetv2.OutputArgs{
			Asset:  n.asset,
			Amount: uint64(n.outputAmount()),
			Script: script,
		}

		return []psetv2.OutputArgs{*output}, nil
	}

	outputs := make([]psetv2.OutputArgs, 0, 2)
	children := n.children()

	for _, child := range children {
		childWitnessProgram, _, err := child.witness()
		if err != nil {
			return nil, err
		}

		script, err := taprootOutputScript(childWitnessProgram)
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, psetv2.OutputArgs{
			Asset:  n.asset,
			Amount: child.inputAmount(),
			Script: script,
		})
	}

	return outputs, nil
}

func (n *node) toNode(input psetv2.InputArgs, tapTree *taproot.IndexedElementsTapScriptTree) (tree.Node, error) {
	pset, err := n.pset(input, tapTree)
	if err != nil {
		return tree.Node{}, err
	}

	txid, err := getPsetId(pset)
	if err != nil {
		return tree.Node{}, err
	}

	tx, err := pset.ToBase64()
	if err != nil {
		return tree.Node{}, err
	}

	parentTxid := chainhash.Hash(pset.Inputs[0].PreviousTxid).String()

	return tree.Node{
		Txid:       txid,
		Tx:         tx,
		ParentTxid: parentTxid,
		Leaf:       n.isLeaf(),
	}, nil
}

// create the node Pset from the previous node Pset represented by input arg
// if node is a branch, it adds two outputs to the Pset, one for the left branch and one for the right branch
// if node is a leaf, it only adds one output to the Pset (the node output)
func (n *node) pset(input psetv2.InputArgs, inputTapTree *taproot.IndexedElementsTapScriptTree) (*psetv2.Pset, error) {
	pset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return nil, err
	}

	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return nil, err
	}

	if err := addTaprootInput(updater, input, tree.UnspendableKey(), inputTapTree); err != nil {
		return nil, err
	}

	feeOutput := psetv2.OutputArgs{
		Amount: uint64(n.feeSats),
		Asset:  n.asset,
	}

	outputs, err := n.outputs()
	if err != nil {
		return nil, err
	}

	if err := updater.AddOutputs(append(outputs, feeOutput)); err != nil {
		return nil, err
	}

	return pset, nil
}

func (n *node) children() []*node {
	if n.isLeaf() {
		return nil
	}

	children := make([]*node, 0, 2)

	if n.left != nil {
		children = append(children, n.left)
	}

	if n.right != nil {
		children = append(children, n.right)
	}

	return children
}

func (n *node) createFinalCongestionTree() treeFactory {
	return func(poolTxInput psetv2.InputArgs) (tree.CongestionTree, error) {
		congestionTree := make(tree.CongestionTree, 0)

		_, taprootTree, err := n.witness()
		if err != nil {
			return nil, err
		}

		ins := []psetv2.InputArgs{poolTxInput}
		inTrees := []*taproot.IndexedElementsTapScriptTree{taprootTree}
		nodes := []*node{n}

		for len(nodes) > 0 {
			nextNodes := make([]*node, 0)
			nextInputsArgs := make([]psetv2.InputArgs, 0)
			nextTaprootTrees := make([]*taproot.IndexedElementsTapScriptTree, 0)

			treeLevel := make([]tree.Node, 0)

			for i, node := range nodes {
				treeNode, err := node.toNode(ins[i], inTrees[i])
				if err != nil {
					return nil, err
				}

				treeLevel = append(treeLevel, treeNode)

				children := node.children()

				for i, child := range children {
					_, taprootTree, err := child.witness()
					if err != nil {
						return nil, err
					}

					nextNodes = append(nextNodes, child)
					nextInputsArgs = append(nextInputsArgs, psetv2.InputArgs{
						Txid:    treeNode.Txid,
						TxIndex: uint32(i),
					})
					nextTaprootTrees = append(nextTaprootTrees, taprootTree)
				}
			}

			congestionTree = append(congestionTree, treeLevel)
			nodes = append([]*node{}, nextNodes...)
			ins = append([]psetv2.InputArgs{}, nextInputsArgs...)
			inTrees = append([]*taproot.IndexedElementsTapScriptTree{}, nextTaprootTrees...)
		}

		return congestionTree, nil
	}
}

func prepareCongestionTree(
	asset string, aspPublicKey *secp256k1.PublicKey,
	payments []domain.Payment, feeSatsPerNode uint64,
) (
	buildCongestionTree treeFactory,
	sharedOutputScript []byte, sharedOutputAmount uint64, err error,
) {
	receivers := getOffchainReceivers(payments)
	root, err := createPartialCongestionTree(
		receivers, aspPublicKey, asset, feeSatsPerNode,
	)
	if err != nil {
		return
	}

	taprootKey, _, err := root.witness()
	if err != nil {
		return
	}

	sharedOutputScript, err = taprootOutputScript(taprootKey)
	if err != nil {
		return
	}
	sharedOutputAmount = root.inputAmount()
	buildCongestionTree = root.createFinalCongestionTree()

	return
}

func createPartialCongestionTree(
	receivers []domain.Receiver,
	aspPublicKey *secp256k1.PublicKey,
	asset string,
	feeSatsPerNode uint64,
) (root *node, err error) {
	if len(receivers) == 0 {
		return nil, fmt.Errorf("no receivers provided")
	}

	nodes := make([]*node, 0, len(receivers))
	for _, r := range receivers {
		leafNode := &node{
			sweepKey:  aspPublicKey,
			receivers: []domain.Receiver{r},
			asset:     asset,
			feeSats:   feeSatsPerNode,
		}
		nodes = append(nodes, leafNode)
	}

	for len(nodes) > 1 {
		nodes, err = createUpperLevel(nodes)
		if err != nil {
			return
		}
	}

	return nodes[0], nil
}

func createUpperLevel(nodes []*node) ([]*node, error) {
	if len(nodes)%2 != 0 {
		last := nodes[len(nodes)-1]
		pairs, err := createUpperLevel(nodes[:len(nodes)-1])
		if err != nil {
			return nil, err
		}

		return append(pairs, last), nil
	}

	pairs := make([]*node, 0, len(nodes)/2)
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		right := nodes[i+1]
		branchNode := &node{
			sweepKey:  left.sweepKey,
			receivers: append(left.receivers, right.receivers...),
			left:      left,
			right:     right,
			asset:     left.asset,
			feeSats:   left.feeSats,
		}
		pairs = append(pairs, branchNode)
	}
	return pairs, nil
}
