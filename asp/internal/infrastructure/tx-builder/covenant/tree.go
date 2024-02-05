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
type pluggableCongestionTree func(outpoint psetv2.InputArgs) (tree.CongestionTree, error)

// buildCongestionTree builder iteratively creates a binary tree of Pset from a set of receivers
// it returns a factory function creating a CongestionTree and the associated output script to be used in the pool transaction
func buildCongestionTree(
	net *network.Network,
	aspPublicKey *secp256k1.PublicKey,
	receivers []domain.Receiver,
	feeSatsPerNode uint64,
) (pluggableTree pluggableCongestionTree, sharedOutputScript []byte, sharedOutputAmount uint64, err error) {
	unspendableKeyBytes, _ := hex.DecodeString(tree.UnspendablePoint)
	unspendableKey, err := secp256k1.ParsePubKey(unspendableKeyBytes)
	if err != nil {
		return nil, nil, 0, err
	}

	root, err := createBinaryTree(receivers, aspPublicKey, unspendableKey, net, feeSatsPerNode)
	if err != nil {
		return nil, nil, 0, err
	}

	taprootKey, taprootTree, err := root.taprootKey()
	if err != nil {
		return nil, nil, 0, err
	}

	sharedOutputScript, err = taprootOutputScript(taprootKey)
	if err != nil {
		return nil, nil, 0, err
	}

	sharedOutputAmount = root.amount()
	if root.isEmpty() {
		sharedOutputAmount += feeSatsPerNode
	}

	return func(outpoint psetv2.InputArgs) (tree.CongestionTree, error) {
		psets, err := createTreeTransactions(root, psetArgs{
			input:       outpoint,
			taprootTree: taprootTree,
		})
		if err != nil {
			return nil, err
		}

		return craftCongestionTreeMatrix(psets)
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

	// cached values
	_taprootKey  *secp256k1.PublicKey
	_taprootTree *taproot.IndexedElementsTapScriptTree
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
	return (n.left == nil || n.left.isEmpty()) && (n.right == nil || n.right.isEmpty())
}

// is it the final node of the tree
func (n *node) isEmpty() bool {
	return n.left == nil && n.right == nil
}

func (n *node) countChildren() int {
	if n.isEmpty() {
		return 0
	}

	result := 0

	if n.left != nil && !n.left.isEmpty() {
		result++
		result += n.left.countChildren()
	}

	if n.right != nil && !n.right.isEmpty() {
		result++
		result += n.right.countChildren()
	}

	return result
}

// compute the output amount of a node = the amount of all its receivers + the fee
func (n *node) amount() uint64 {
	var amount uint64
	for _, r := range n.receivers {
		amount += r.Amount
	}

	if n.isEmpty() {
		return amount
	}

	nb := uint64(n.countChildren())

	return amount + (nb+1)*n.feeSats

}

func (n *node) taprootKey() (*secp256k1.PublicKey, *taproot.IndexedElementsTapScriptTree, error) {
	if n._taprootKey != nil && n._taprootTree != nil {
		return n._taprootKey, n._taprootTree, nil
	}

	sweepTaprootLeaf, err := tree.SweepScript(n.sweepKey, expirationTime)
	if err != nil {
		return nil, nil, err
	}

	if n.isEmpty() {
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

		leafTaprootTree := taproot.AssembleTaprootScriptTree(*vtxoLeaf, *sweepTaprootLeaf)
		root := leafTaprootTree.RootNode.TapHash()

		taprootKey := taproot.ComputeTaprootOutputKey(
			n.internalTaprootKey,
			root[:],
		)

		n._taprootKey = taprootKey
		n._taprootTree = leafTaprootTree

		return taprootKey, leafTaprootTree, nil
	}

	leftKey, _, err := n.left.taprootKey()
	if err != nil {
		return nil, nil, err
	}

	rightKey, _, err := n.right.taprootKey()
	if err != nil {
		return nil, nil, err
	}

	branchTaprootLeaf := tree.BranchScript(
		leftKey, rightKey, n.left.amount(), n.right.amount(),
	)

	branchTaprootTree := taproot.AssembleTaprootScriptTree(branchTaprootLeaf, *sweepTaprootLeaf)
	root := branchTaprootTree.RootNode.TapHash()

	taprootKey := taproot.ComputeTaprootOutputKey(
		n.internalTaprootKey,
		root[:],
	)

	n._taprootKey = taprootKey
	n._taprootTree = branchTaprootTree

	return taprootKey, branchTaprootTree, nil
}

// compute the output script of a node
func (n *node) script() ([]byte, error) {
	taprootKey, _, err := n.taprootKey()
	if err != nil {
		return nil, err
	}

	return taprootOutputScript(taprootKey)
}

// use script & amount() to create OutputArgs
func (n *node) output() (*psetv2.OutputArgs, error) {
	script, err := n.script()
	if err != nil {
		return nil, err
	}

	return &psetv2.OutputArgs{
		Asset:  n.network.AssetID,
		Amount: uint64(n.amount()),
		Script: script,
	}, nil
}

type psetArgs struct {
	input       psetv2.InputArgs
	taprootTree *taproot.IndexedElementsTapScriptTree
}

// create the node Pset from the previous node Pset represented by input arg
// if node is a branch, it adds two outputs to the Pset, one for the left branch and one for the right branch
// if node is a leaf, it only adds one output to the Pset (the node output)
func (n *node) pset(args psetArgs) (*psetv2.Pset, error) {
	pset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return nil, err
	}

	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return nil, err
	}

	if err := addTaprootInput(updater, args.input, n.internalTaprootKey, args.taprootTree); err != nil {
		return nil, err
	}

	feeOutput := psetv2.OutputArgs{
		Amount: uint64(n.feeSats),
		Asset:  n.network.AssetID,
	}

	if n.isEmpty() {
		output, err := n.output()
		if err != nil {
			return nil, err
		}

		err = updater.AddOutputs([]psetv2.OutputArgs{*output, feeOutput})
		if err != nil {
			return nil, err
		}
		return pset, nil
	}

	outputLeft, err := n.left.output()
	if err != nil {
		return nil, err
	}

	outputRight, err := n.right.output()
	if err != nil {
		return nil, err
	}

	err = updater.AddOutputs([]psetv2.OutputArgs{*outputLeft, *outputRight, feeOutput})
	if err != nil {
		return nil, err
	}

	return pset, nil
}

type psetWithLevel struct {
	pset  *psetv2.Pset
	level int
	leaf  bool
}

func createTreeTransactions(root *node, poolTxInput psetArgs) ([]psetWithLevel, error) {
	transactions := make([]psetWithLevel, 0)

	inputArgs := []psetArgs{poolTxInput}
	nodes := []*node{root}

	level := 0

	for len(nodes) > 0 {
		nextNodes := make([]*node, 0)
		nextInputsArgs := make([]psetArgs, 0)

		for i, node := range nodes {
			pset, err := node.pset(inputArgs[i])
			if err != nil {
				return nil, err
			}

			txid, err := getPsetId(pset)
			if err != nil {
				return nil, err
			}

			isLeaf := node.isLeaf() || node.left.isEmpty() || node.right.isEmpty()
			transactions = append(transactions, psetWithLevel{pset, level, isLeaf})
			children := node.children()

			for i, child := range children {
				_, taprootTree, err := child.taprootKey()
				if err != nil {
					return nil, err
				}

				nextNodes = append(nextNodes, child)
				nextInputsArgs = append(nextInputsArgs, psetArgs{
					input: psetv2.InputArgs{
						Txid:    txid,
						TxIndex: uint32(i),
					},
					taprootTree: taprootTree,
				})
			}
		}

		level++
		nodes = nextNodes
		inputArgs = nextInputsArgs
	}

	return transactions, nil
}

func (n *node) children() []*node {
	if n.isEmpty() {
		return []*node{}
	}

	children := make([]*node, 0, 2)

	if !n.left.isEmpty() {
		children = append(children, n.left)
	}

	if !n.right.isEmpty() {
		children = append(children, n.right)
	}

	return children
}

func craftCongestionTreeMatrix(psetsWithLevel []psetWithLevel) (tree.CongestionTree, error) {
	maxLevel := 0
	for _, psetWithLevel := range psetsWithLevel {
		if psetWithLevel.level > maxLevel {
			maxLevel = psetWithLevel.level
		}
	}

	congestionTree := make(tree.CongestionTree, maxLevel+1)

	for _, psetWithLevel := range psetsWithLevel {
		utx, err := psetWithLevel.pset.UnsignedTx()
		if err != nil {
			return nil, err
		}

		txid := utx.TxHash().String()

		psetB64, err := psetWithLevel.pset.ToBase64()
		if err != nil {
			return nil, err
		}

		parentTxid := chainhash.Hash(psetWithLevel.pset.Inputs[0].PreviousTxid).String()

		if len(congestionTree) <= psetWithLevel.level {
			congestionTree[psetWithLevel.level] = make([]tree.Node, 0)
		}

		congestionTree[psetWithLevel.level] = append(congestionTree[psetWithLevel.level], tree.Node{
			Txid:       txid,
			Tx:         psetB64,
			ParentTxid: parentTxid,
			Leaf:       psetWithLevel.leaf,
		})
	}

	return congestionTree, nil
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

func getPsetId(pset *psetv2.Pset) (string, error) {
	utx, err := pset.UnsignedTx()
	if err != nil {
		return "", err
	}

	return utx.TxHash().String(), nil
}
