package tree

import (
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
)

func BuildVtxoTree(
	asset string, serverPubkey *secp256k1.PublicKey, receivers []VtxoLeaf,
	feeSatsPerNode uint64, vtxoTreeExpiry common.RelativeLocktime,
) (
	factoryFn TreeFactory,
	sharedOutputScript []byte, sharedOutputAmount uint64, err error,
) {
	root, err := buildTreeNodes(
		asset, serverPubkey, receivers, feeSatsPerNode, vtxoTreeExpiry,
	)
	if err != nil {
		return
	}

	taprootKey, _, err := root.getWitnessData()
	if err != nil {
		return
	}

	sharedOutputScript, err = taprootOutputScript(taprootKey)
	if err != nil {
		return
	}
	sharedOutputAmount = root.getAmount() + root.feeSats
	factoryFn = root.buildVtxoTree()

	return
}

type vtxoOutput struct {
	pubkey *secp256k1.PublicKey
	amount uint64
}

type node struct {
	sweepKey       *secp256k1.PublicKey
	receivers      []vtxoOutput
	left           *node
	right          *node
	asset          string
	feeSats        uint64
	vtxoTreeExpiry common.RelativeLocktime

	_inputTaprootKey  *secp256k1.PublicKey
	_inputTaprootTree *taproot.IndexedElementsTapScriptTree
}

func (n *node) isLeaf() bool {
	return len(n.receivers) == 1
}

func (n *node) getAmount() uint64 {
	var amount uint64
	for _, r := range n.receivers {
		amount += r.amount
	}

	if n.isLeaf() {
		return amount
	}

	return amount + n.feeSats*uint64(n.countChildren())
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

func (n *node) getChildren() []*node {
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

func (n *node) getOutputs() ([]psetv2.OutputArgs, error) {
	if n.isLeaf() {
		taprootKey, err := n.getVtxoWitnessData()
		if err != nil {
			return nil, err
		}

		script, err := taprootOutputScript(taprootKey)
		if err != nil {
			return nil, err
		}

		output := &psetv2.OutputArgs{
			Asset:  n.asset,
			Amount: uint64(n.getAmount()),
			Script: script,
		}

		return []psetv2.OutputArgs{*output}, nil
	}

	outputs := make([]psetv2.OutputArgs, 0, 2)
	children := n.getChildren()

	for _, child := range children {
		childWitnessProgram, _, err := child.getWitnessData()
		if err != nil {
			return nil, err
		}

		script, err := taprootOutputScript(childWitnessProgram)
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, psetv2.OutputArgs{
			Asset:  n.asset,
			Amount: child.getAmount() + child.feeSats,
			Script: script,
		})
	}

	return outputs, nil
}

func (n *node) getWitnessData() (
	*secp256k1.PublicKey, *taproot.IndexedElementsTapScriptTree, error,
) {
	if n._inputTaprootKey != nil && n._inputTaprootTree != nil {
		return n._inputTaprootKey, n._inputTaprootTree, nil
	}

	sweepClosure := &CSVMultisigClosure{
		MultisigClosure: MultisigClosure{PubKeys: []*secp256k1.PublicKey{n.sweepKey}},
		Locktime:        n.vtxoTreeExpiry,
	}

	sweepLeaf, err := sweepClosure.Script()
	if err != nil {
		return nil, nil, err
	}

	if n.isLeaf() {
		taprootKey, err := n.getVtxoWitnessData()
		if err != nil {
			return nil, nil, err
		}

		unrollClosure := &UnrollClosure{
			LeftKey:     taprootKey,
			MinRelayFee: n.feeSats,
		}

		unrollScript, err := unrollClosure.Script()
		if err != nil {
			return nil, nil, err
		}

		branchTaprootTree := taproot.AssembleTaprootScriptTree(
			taproot.NewBaseTapElementsLeaf(unrollScript),
			taproot.NewBaseTapElementsLeaf(sweepLeaf),
		)
		root := branchTaprootTree.RootNode.TapHash()

		inputTapkey := taproot.ComputeTaprootOutputKey(
			UnspendableKey(),
			root[:],
		)

		n._inputTaprootKey = inputTapkey
		n._inputTaprootTree = branchTaprootTree

		return inputTapkey, branchTaprootTree, nil
	}

	leftKey, _, err := n.left.getWitnessData()
	if err != nil {
		return nil, nil, err
	}

	rightKey, _, err := n.right.getWitnessData()
	if err != nil {
		return nil, nil, err
	}

	leftAmount := n.left.getAmount() + n.feeSats
	rightAmount := n.right.getAmount() + n.feeSats

	unrollClosure := &UnrollClosure{
		LeftKey:     leftKey,
		LeftAmount:  leftAmount,
		RightKey:    rightKey,
		RightAmount: rightAmount,
	}

	unrollLeaf, err := unrollClosure.Script()
	if err != nil {
		return nil, nil, err
	}

	branchTaprootTree := taproot.AssembleTaprootScriptTree(
		taproot.NewBaseTapElementsLeaf(unrollLeaf),
		taproot.NewBaseTapElementsLeaf(sweepLeaf),
	)
	root := branchTaprootTree.RootNode.TapHash()

	taprootKey := taproot.ComputeTaprootOutputKey(
		UnspendableKey(),
		root[:],
	)

	n._inputTaprootKey = taprootKey
	n._inputTaprootTree = branchTaprootTree

	return taprootKey, branchTaprootTree, nil
}

func (n *node) getVtxoWitnessData() (
	*secp256k1.PublicKey, error,
) {
	if !n.isLeaf() {
		return nil, fmt.Errorf("cannot call vtxoWitness on a non-leaf node")
	}

	receiver := n.receivers[0]
	return receiver.pubkey, nil
}

func (n *node) getTreeNode(
	input psetv2.InputArgs, tapTree *taproot.IndexedElementsTapScriptTree,
) (Node, error) {
	pset, err := n.getTx(input, tapTree)
	if err != nil {
		return Node{}, err
	}

	txid, err := getPsetId(pset)
	if err != nil {
		return Node{}, err
	}

	tx, err := pset.ToBase64()
	if err != nil {
		return Node{}, err
	}
	parentTxid := chainhash.Hash(pset.Inputs[0].PreviousTxid).String()

	return Node{
		Txid:       txid,
		Tx:         tx,
		ParentTxid: parentTxid,
		Leaf:       n.isLeaf(),
	}, nil
}

func (n *node) getTx(
	input psetv2.InputArgs, inputTapTree *taproot.IndexedElementsTapScriptTree,
) (*psetv2.Pset, error) {
	pset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return nil, err
	}

	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return nil, err
	}

	if err := addTaprootInput(
		updater, input, UnspendableKey(), inputTapTree,
	); err != nil {
		return nil, err
	}

	feeOutput := psetv2.OutputArgs{
		Amount: uint64(n.feeSats),
		Asset:  n.asset,
	}

	outputs, err := n.getOutputs()
	if err != nil {
		return nil, err
	}

	if err := updater.AddOutputs(append(outputs, feeOutput)); err != nil {
		return nil, err
	}

	return pset, nil
}

func (n *node) buildVtxoTree() TreeFactory {
	return func(roundTxInput psetv2.InputArgs) (VtxoTree, error) {
		vtxoTree := make(VtxoTree, 0)

		_, taprootTree, err := n.getWitnessData()
		if err != nil {
			return nil, err
		}

		ins := []psetv2.InputArgs{roundTxInput}
		inTrees := []*taproot.IndexedElementsTapScriptTree{taprootTree}
		nodes := []*node{n}

		for len(nodes) > 0 {
			nextNodes := make([]*node, 0)
			nextInputsArgs := make([]psetv2.InputArgs, 0)
			nextTaprootTrees := make([]*taproot.IndexedElementsTapScriptTree, 0)

			treeLevel := make([]Node, 0)

			for i, node := range nodes {
				treeNode, err := node.getTreeNode(ins[i], inTrees[i])
				if err != nil {
					return nil, err
				}

				treeLevel = append(treeLevel, treeNode)

				children := node.getChildren()

				for i, child := range children {
					_, taprootTree, err := child.getWitnessData()
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

			vtxoTree = append(vtxoTree, treeLevel)
			nodes = append([]*node{}, nextNodes...)
			ins = append([]psetv2.InputArgs{}, nextInputsArgs...)
			inTrees = append(
				[]*taproot.IndexedElementsTapScriptTree{}, nextTaprootTrees...,
			)
		}

		return vtxoTree, nil
	}
}

func buildTreeNodes(
	asset string, serverPubkey *secp256k1.PublicKey, receivers []VtxoLeaf,
	feeSatsPerNode uint64, vtxoTreeExpiry common.RelativeLocktime,
) (root *node, err error) {
	if len(receivers) == 0 {
		return nil, fmt.Errorf("no receivers provided")
	}

	nodes := make([]*node, 0, len(receivers))
	for _, r := range receivers {
		pubkeyBytes, err := hex.DecodeString(r.PubKey)
		if err != nil {
			return nil, err
		}

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return nil, err
		}

		leafNode := &node{
			sweepKey:       serverPubkey,
			receivers:      []vtxoOutput{{pubkey, r.Amount}},
			asset:          asset,
			feeSats:        feeSatsPerNode,
			vtxoTreeExpiry: vtxoTreeExpiry,
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
			sweepKey:       left.sweepKey,
			receivers:      append(left.receivers, right.receivers...),
			left:           left,
			right:          right,
			asset:          left.asset,
			feeSats:        left.feeSats,
			vtxoTreeExpiry: left.vtxoTreeExpiry,
		}
		pairs = append(pairs, branchNode)
	}
	return pairs, nil
}

func taprootOutputScript(taprootKey *secp256k1.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_1).AddData(
		schnorr.SerializePubKey(taprootKey),
	).Script()
}

func getPsetId(pset *psetv2.Pset) (string, error) {
	utx, err := pset.UnsignedTx()
	if err != nil {
		return "", err
	}

	return utx.TxHash().String(), nil
}

func addTaprootInput(
	updater *psetv2.Updater, input psetv2.InputArgs,
	internalTaprootKey *secp256k1.PublicKey,
	taprootTree *taproot.IndexedElementsTapScriptTree,
) error {
	if err := updater.AddInputs([]psetv2.InputArgs{input}); err != nil {
		return err
	}

	if err := updater.AddInTapInternalKey(
		0, schnorr.SerializePubKey(internalTaprootKey),
	); err != nil {
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
