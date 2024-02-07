package txbuilder

import (
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
)

const (
	expirationTime = 60 * 60 * 24 * 14 // 14 days in seconds
)

// the private method buildCongestionTree returns a function letting to plug in the pool transaction output as input of the tree's root node
type treeFactory func(outpoint psetv2.InputArgs) (tree.CongestionTree, error)

// prepareCongestionTree builder iteratively creates a binary tree of Pset from a set of receivers
// it returns a factory function creating a CongestionTree and the associated output script to be used in the pool transaction
func prepareCongestionTree(
	net *network.Network,
	aspPublicKey *secp256k1.PublicKey,
	payments []domain.Payment,
	feeSatsPerNode uint64,
) (buildCongestionTree treeFactory, sharedOutputScript []byte, sharedOutputAmount uint64, err error) {
	unspendableKey := tree.UnspendableKey()

	receivers := getOffchainReceivers(payments)

	root, err := createBinaryTree(receivers, aspPublicKey, unspendableKey, net, feeSatsPerNode)
	if err != nil {
		return nil, nil, 0, err
	}

	taprootKey, taprootTree, err := root.inputTaprootKey()
	if err != nil {
		return nil, nil, 0, err
	}

	sharedOutputScript, err = taprootOutputScript(taprootKey)
	if err != nil {
		return nil, nil, 0, err
	}

	sharedOutputAmount = root.inputAmount()

	return func(outpoint psetv2.InputArgs) (tree.CongestionTree, error) {
		congestionTree, err := createCongestionTree(root, outpoint, taprootTree)
		if err != nil {
			return nil, err
		}

		return congestionTree, nil
	}, sharedOutputScript, sharedOutputAmount, nil
}

// internal struct to build a binary tree of Pset
type node struct {
	internalTaprootKey *secp256k1.PublicKey
	sweepKey           *secp256k1.PublicKey
	receivers          []domain.Receiver
	left               *node
	right              *node
	network            *network.Network
	feeSats            uint64
}

// create a node from a single receiver
func newLeaf(
	network *network.Network,
	internalKey *secp256k1.PublicKey,
	sweepKey *secp256k1.PublicKey,
	receiver domain.Receiver,
	feeSats uint64,
) *node {
	return &node{
		sweepKey:           sweepKey,
		internalTaprootKey: internalKey,
		receivers:          []domain.Receiver{receiver},
		network:            network,
		feeSats:            feeSats,
	}
}

// aggregate two nodes into a branch node
func newBranch(
	left *node,
	right *node,
) *node {
	return &node{
		internalTaprootKey: left.internalTaprootKey,
		sweepKey:           left.sweepKey,
		receivers:          append(left.receivers, right.receivers...),
		left:               left,
		right:              right,
		network:            left.network,
		feeSats:            left.feeSats,
	}
}

func (n *node) isLeaf() bool {
	return len(n.receivers) == 1
}

func (n *node) countChildren() int {
	if n.isLeaf() {
		return 0
	}

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

// compute the output outputAmount of a node = the outputAmount of all its receivers + the fee
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
func (n *node) inputTaprootKey() (*secp256k1.PublicKey, *taproot.IndexedElementsTapScriptTree, error) {
	sweepTaprootLeaf, err := tree.SweepScript(n.sweepKey, expirationTime)
	if err != nil {
		return nil, nil, err
	}

	if n.isLeaf() {
		taprootKey, _, err := n.leafTaprootKey()
		if err != nil {
			return nil, nil, err
		}

		branchTaprootScript := tree.BranchScript(
			taprootKey, nil, n.outputAmount(), 0,
		)

		branchTaprootTree := taproot.AssembleTaprootScriptTree(branchTaprootScript, *sweepTaprootLeaf)
		root := branchTaprootTree.RootNode.TapHash()

		inputTapkey := taproot.ComputeTaprootOutputKey(
			n.internalTaprootKey,
			root[:],
		)

		return inputTapkey, branchTaprootTree, nil
	}

	leftKey, _, err := n.left.inputTaprootKey()
	if err != nil {
		return nil, nil, err
	}

	rightKey, _, err := n.right.inputTaprootKey()
	if err != nil {
		return nil, nil, err
	}

	branchTaprootLeaf := tree.BranchScript(
		leftKey, rightKey, n.left.inputAmount(), n.right.inputAmount(),
	)

	branchTaprootTree := taproot.AssembleTaprootScriptTree(branchTaprootLeaf, *sweepTaprootLeaf)
	root := branchTaprootTree.RootNode.TapHash()

	taprootKey := taproot.ComputeTaprootOutputKey(
		n.internalTaprootKey,
		root[:],
	)

	return taprootKey, branchTaprootTree, nil
}

func (n *node) leafTaprootKey() (*secp256k1.PublicKey, *taproot.IndexedElementsTapScriptTree, error) {
	if !n.isLeaf() {
		return nil, nil, fmt.Errorf("cannot call leafTaprootKey on a non-leaf node")
	}

	sweepTaprootLeaf, err := tree.SweepScript(n.sweepKey, expirationTime)
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
	leafTaprootTree := taproot.AssembleTaprootScriptTree(*vtxoLeaf, *sweepTaprootLeaf)
	root := leafTaprootTree.RootNode.TapHash()

	taprootKey := taproot.ComputeTaprootOutputKey(
		n.internalTaprootKey,
		root[:],
	)

	return taprootKey, leafTaprootTree, nil
}

func (n *node) inputScript() ([]byte, error) {
	taprootKey, _, err := n.inputTaprootKey()
	if err != nil {
		return nil, err
	}

	return taprootOutputScript(taprootKey)
}

func (n *node) leafOutputScript() ([]byte, error) {
	taprootKey, _, err := n.leafTaprootKey()
	if err != nil {
		return nil, err
	}

	return taprootOutputScript(taprootKey)
}

func (n *node) leafOutput() (*psetv2.OutputArgs, error) {
	script, err := n.leafOutputScript()
	if err != nil {
		return nil, err
	}

	output := &psetv2.OutputArgs{
		Asset:  n.network.AssetID,
		Amount: uint64(n.outputAmount()),
		Script: script,
	}

	return output, nil
}

// returns the outputs of the node's pset
func (n *node) outputs() ([]psetv2.OutputArgs, error) {
	if n.isLeaf() {
		output, err := n.leafOutput()
		if err != nil {
			return nil, err
		}

		return []psetv2.OutputArgs{*output}, nil
	}

	outputs := make([]psetv2.OutputArgs, 0, 2)
	children := n.children()

	for _, child := range children {
		script, err := child.inputScript()
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, psetv2.OutputArgs{
			Asset:  n.network.AssetID,
			Amount: child.inputAmount(),
			Script: script,
		})
	}

	return outputs, nil
}

func (n *node) toMatrixNode(input psetv2.InputArgs, tapTree *taproot.IndexedElementsTapScriptTree) (tree.Node, error) {
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

	if err := addTaprootInput(updater, input, n.internalTaprootKey, inputTapTree); err != nil {
		return nil, err
	}

	feeOutput := psetv2.OutputArgs{
		Amount: uint64(n.feeSats),
		Asset:  n.network.AssetID,
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

func createCongestionTree(
	root *node,
	poolTxInput psetv2.InputArgs,
	poolTxTaprootTree *taproot.IndexedElementsTapScriptTree,
) (tree.CongestionTree, error) {
	congestionTree := make(tree.CongestionTree, 0)

	inputArgs := []psetv2.InputArgs{poolTxInput}
	inputTaprootTrees := []*taproot.IndexedElementsTapScriptTree{poolTxTaprootTree}
	nodes := []*node{root}

	for len(nodes) > 0 {
		nextNodes := make([]*node, 0)
		nextInputsArgs := make([]psetv2.InputArgs, 0)
		nextTaprootTrees := make([]*taproot.IndexedElementsTapScriptTree, 0)

		treeLevel := make([]tree.Node, 0)

		for i, node := range nodes {
			matrixNode, err := node.toMatrixNode(inputArgs[i], inputTaprootTrees[i])
			if err != nil {
				return nil, err
			}

			treeLevel = append(treeLevel, matrixNode)

			children := node.children()

			for i, child := range children {
				_, taprootTree, err := child.inputTaprootKey()
				if err != nil {
					return nil, err
				}

				nextNodes = append(nextNodes, child)
				nextInputsArgs = append(nextInputsArgs, psetv2.InputArgs{
					Txid:    matrixNode.Txid,
					TxIndex: uint32(i),
				})
				nextTaprootTrees = append(nextTaprootTrees, taprootTree)
			}
		}

		congestionTree = append(congestionTree, treeLevel)
		nodes = append([]*node{}, nextNodes...)
		inputArgs = append([]psetv2.InputArgs{}, nextInputsArgs...)
		inputTaprootTrees = append([]*taproot.IndexedElementsTapScriptTree{}, nextTaprootTrees...)
	}

	return congestionTree, nil
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

// createBinaryTree returns the root node of a binary tree containing all the receivers
func createBinaryTree(
	receivers []domain.Receiver,
	aspPublicKey,
	unspendableKey *secp256k1.PublicKey,
	net *network.Network,
	feeSatsPerNode uint64,
) (root *node, err error) {
	if len(receivers) == 0 {
		return nil, fmt.Errorf("no receivers provided")
	}

	nodes := make([]*node, 0, len(receivers))
	for _, r := range receivers {
		nodes = append(nodes, newLeaf(net, unspendableKey, aspPublicKey, r, feeSatsPerNode))
	}

	for len(nodes) > 1 {
		nodes, err = createNextTreeLevel(nodes)
		if err != nil {
			return
		}
	}

	return nodes[0], nil
}

func createNextTreeLevel(nodes []*node) ([]*node, error) {
	if len(nodes)%2 != 0 {
		last := nodes[len(nodes)-1]
		pairs, err := createNextTreeLevel(nodes[:len(nodes)-1])
		if err != nil {
			return nil, err
		}

		return append(pairs, last), nil
	}

	pairs := make([]*node, 0, len(nodes)/2)
	for i := 0; i < len(nodes); i += 2 {
		pairs = append(pairs, newBranch(nodes[i], nodes[i+1]))
	}
	return pairs, nil
}

func taprootOutputScript(taprootKey *secp256k1.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(taprootKey)).Script()
}

// wrapper of updater methods adding a taproot input to the pset with all the necessary data to spend it via any taproot script
func addTaprootInput(
	updater *psetv2.Updater,
	input psetv2.InputArgs,
	internalTaprootKey *secp256k1.PublicKey,
	taprootTree *taproot.IndexedElementsTapScriptTree,
) error {
	if err := updater.AddInputs([]psetv2.InputArgs{input}); err != nil {
		return err
	}

	if err := updater.AddInTapInternalKey(0, schnorr.SerializePubKey(internalTaprootKey)); err != nil {
		return err
	}

	for _, proof := range taprootTree.LeafMerkleProofs {
		controlBlock := proof.ToControlBlock(internalTaprootKey)

		if err := updater.AddInTapLeafScript(0, psetv2.TapLeafScript{
			TapElementsLeaf: taproot.NewBaseTapElementsLeaf(proof.Script),
			ControlBlock:    controlBlock,
		}); err != nil {
			return err
		}
	}

	return nil
}
