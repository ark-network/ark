package txbuilder

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/ark-network/ark/common"
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
	sharedOutputIndex            = 0
	OP_INSPECTOUTPUTSCRIPTPUBKEY = 0xd1
	OP_INSPECTOUTPUTVALUE        = 0xcf
	OP_PUSHCURRENTINPUTINDEX     = 0xcd
	unspendablePoint             = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
	timeDelta                    = 60 * 60 * 24 * 7 // 7 days in seconds
)

type outputScriptFactory func(leaves []domain.Receiver) ([]byte, error)

func withOutput(outputIndex uint64, taprootWitnessProgram []byte, amount uint32, verify bool) []byte {
	amountBuffer := make([]byte, 8)
	binary.LittleEndian.PutUint32(amountBuffer, amount)

	index := scriptNum(outputIndex).Bytes()

	script := append(index, []byte{
		OP_INSPECTOUTPUTSCRIPTPUBKEY,
		txscript.OP_1,
		txscript.OP_EQUALVERIFY,
		txscript.OP_DATA_32,
	}...)

	script = append(script, taprootWitnessProgram...)
	script = append(script, []byte{
		txscript.OP_EQUALVERIFY,
	}...)
	script = append(script, index...)
	script = append(script, []byte{
		OP_INSPECTOUTPUTVALUE,
		txscript.OP_1,
		txscript.OP_EQUALVERIFY,
		txscript.OP_DATA_8,
	}...)
	script = append(script, amountBuffer...)
	if verify {
		script = append(script, []byte{
			txscript.OP_EQUALVERIFY,
		}...)
	} else {
		script = append(script, []byte{
			txscript.OP_EQUAL,
		}...)
	}

	return script
}

func checksigScript(pubkey *secp256k1.PublicKey) ([]byte, error) {
	key := schnorr.SerializePubKey(pubkey)
	return txscript.NewScriptBuilder().AddData(key).AddOp(txscript.OP_CHECKSIG).Script()
}

func checkSequenceVerifyScript(seconds uint) ([]byte, error) {
	sequence, err := common.BIP68Encode(seconds)
	if err != nil {
		return nil, err
	}

	return append(sequence, []byte{
		txscript.OP_CHECKSEQUENCEVERIFY,
		txscript.OP_DROP,
	}...), nil
}

func csvChecksigScript(pubkey *secp256k1.PublicKey, seconds uint) ([]byte, error) {
	script, err := checksigScript(pubkey)
	if err != nil {
		return nil, err
	}

	csvScript, err := checkSequenceVerifyScript(seconds)
	if err != nil {
		return nil, err
	}

	return append(csvScript, script...), nil
}

// congestionTree builder iteratively creates a binary tree of Pset from a set of receivers
// it also expect createOutputScript func managing the output script creation and the network to use (mainly for L-BTC asset id)
func buildCongestionTree(
	net *network.Network,
	aspPublicKey *secp256k1.PublicKey,
	poolTxID string,
	receivers []domain.Receiver,
) (congestionTree domain.CongestionTree, err error) {
	unspendableKeyBytes, err := hex.DecodeString(unspendablePoint)
	if err != nil {
		return nil, err
	}

	unspendableKey, err := secp256k1.ParsePubKey(unspendableKeyBytes)
	if err != nil {
		return nil, err
	}

	var nodes []*node

	for _, r := range receivers {
		nodes = append(nodes, newLeaf(net, unspendableKey, aspPublicKey, r))
	}

	for len(nodes) > 1 {
		nodes, err = createTreeLevel(nodes)
		if err != nil {
			return nil, err
		}
	}

	psets, err := nodes[0].psets(
		psetArgs{
			input: psetv2.InputArgs{
				Txid:    poolTxID,
				TxIndex: sharedOutputIndex,
			},
			taprootTree: nil,
			nodeTimeout: timeDelta,
		}, 0)
	if err != nil {
		return nil, err
	}

	maxLevel := 0
	for _, psetWithLevel := range psets {
		if psetWithLevel.level > maxLevel {
			maxLevel = psetWithLevel.level
		}
	}

	tree := make(domain.CongestionTree, maxLevel+1)

	for _, psetWithLevel := range psets {
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

		tree[psetWithLevel.level] = append(tree[psetWithLevel.level], domain.Node{
			Txid:       txid,
			Tx:         psetB64,
			ParentTxid: parentTxid,
		})
	}

	return tree, nil
}

func createTreeLevel(nodes []*node) ([]*node, error) {
	if len(nodes)%2 != 0 {
		last := nodes[len(nodes)-1]
		pairs, err := createTreeLevel(nodes[:len(nodes)-1])
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

// internal struct to build a binary tree of Pset
type node struct {
	internalTaprootKey *secp256k1.PublicKey
	sweepKey           *secp256k1.PublicKey
	receivers          []domain.Receiver
	left               *node
	right              *node
	network            *network.Network

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
) *node {
	return &node{
		internalTaprootKey: internalKey,
		receivers:          []domain.Receiver{receiver},
		network:            network,
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
	}
}

// is it the final node of the tree
func (n *node) isLeaf() bool {
	return len(n.receivers) == 1
}

// compute the output amount of a node
func (n *node) amount() uint32 {
	var amount uint32
	for _, r := range n.receivers {
		amount += uint32(r.Amount)
	}
	return amount
}

func (n *node) taprootKey(timeoutSeconds uint) (*secp256k1.PublicKey, *taproot.IndexedElementsTapScriptTree, error) {
	if n._taprootKey != nil && n._taprootTree != nil {
		return n._taprootKey, n._taprootTree, nil
	}

	sweepScript, err := csvChecksigScript(n.sweepKey, timeoutSeconds)
	if err != nil {
		return nil, nil, err
	}
	sweepTaprootLeaf := taproot.NewBaseTapElementsLeaf(sweepScript)

	if n.isLeaf() {
		_, key, err := common.DecodePubKey(n.receivers[0].Pubkey)
		if err != nil {
			return nil, nil, err
		}

		leafScript, err := checksigScript(key)
		if err != nil {
			return nil, nil, err
		}

		leafTaprootLeaf := taproot.NewBaseTapElementsLeaf(leafScript)
		leafTaprootTree := taproot.AssembleTaprootScriptTree(leafTaprootLeaf, sweepTaprootLeaf)
		root := leafTaprootTree.RootNode.TapHash()

		taprootKey := taproot.ComputeTaprootOutputKey(
			n.internalTaprootKey,
			root[:],
		)

		n._taprootKey = taprootKey
		n._taprootTree = leafTaprootTree

		return taprootKey, leafTaprootTree, nil
	}

	leftKey, _, err := n.left.taprootKey(timeoutSeconds)
	if err != nil {
		return nil, nil, err
	}

	rightKey, _, err := n.right.taprootKey(timeoutSeconds)
	if err != nil {
		return nil, nil, err
	}

	nextScriptLeft := withOutput(0, schnorr.SerializePubKey(leftKey), n.left.amount(), true)
	nextScriptRight := withOutput(1, schnorr.SerializePubKey(rightKey), n.right.amount(), false)
	branchScript := append(nextScriptLeft, nextScriptRight...)
	branchTaprootLeaf := taproot.NewBaseTapElementsLeaf(branchScript)

	branchTaprootTree := taproot.AssembleTaprootScriptTree(branchTaprootLeaf, sweepTaprootLeaf)
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
func (n *node) script(timeoutSeconds uint) ([]byte, error) {
	taprootKey, _, err := n.taprootKey(timeoutSeconds)
	if err != nil {
		return nil, err
	}

	return txscript.NewScriptBuilder().AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(taprootKey)).Script()
}

// use script & amount to create OutputArgs
func (n *node) output(timeoutSeconds uint) (*psetv2.OutputArgs, error) {
	script, err := n.script(timeoutSeconds)
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
	nodeTimeout uint
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

	err = updater.AddInputs([]psetv2.InputArgs{args.input})
	if err != nil {
		return nil, err
	}

	err = updater.AddInTapInternalKey(0, schnorr.SerializePubKey(n.internalTaprootKey))
	if err != nil {
		return nil, err
	}

	for _, proof := range args.taprootTree.LeafMerkleProofs {
		controlBlock := proof.ToControlBlock(n.internalTaprootKey)

		err = updater.AddInTapLeafScript(0, psetv2.TapLeafScript{
			TapElementsLeaf: taproot.NewBaseTapElementsLeaf(proof.Script),
			ControlBlock:    controlBlock,
		})
		if err != nil {
			return nil, err
		}
	}

	if n.isLeaf() {
		output, err := n.output(args.nodeTimeout)
		if err != nil {
			return nil, err
		}

		err = updater.AddOutputs([]psetv2.OutputArgs{*output})
		if err != nil {
			return nil, err
		}
		return pset, nil
	}

	outputLeft, err := n.left.output(args.nodeTimeout)
	if err != nil {
		return nil, err
	}

	outputRight, err := n.right.output(args.nodeTimeout)
	if err != nil {
		return nil, err
	}

	err = updater.AddOutputs([]psetv2.OutputArgs{*outputLeft, *outputRight})
	if err != nil {
		return nil, err
	}

	return pset, nil
}

type psetWithLevel struct {
	pset  *psetv2.Pset
	level int
}

// create the node pset and all the psets of its children recursively, updating the input arg at each step
// the function stops when it reaches a leaf node
func (n *node) psets(inputArgs psetArgs, level int) ([]psetWithLevel, error) {
	pset, err := n.pset(inputArgs)
	if err != nil {
		return nil, err
	}

	nodeResult := []psetWithLevel{
		{pset, level},
	}

	if n.isLeaf() {
		return nodeResult, nil
	}

	unsignedTx, err := pset.UnsignedTx()
	if err != nil {
		return nil, err
	}

	txID := unsignedTx.TxHash().String()

	_, taprootTree, err := n.taprootKey(inputArgs.nodeTimeout)

	psetsLeft, err := n.left.psets(psetArgs{
		input: psetv2.InputArgs{
			Txid:    txID,
			TxIndex: 0,
		},
		taprootTree: taprootTree,
		nodeTimeout: inputArgs.nodeTimeout + timeDelta,
	}, level+1)
	if err != nil {
		return nil, err
	}

	psetsRight, err := n.right.psets(psetArgs{
		input: psetv2.InputArgs{
			Txid:    txID,
			TxIndex: 1,
		},
		taprootTree: taprootTree,
		nodeTimeout: inputArgs.nodeTimeout + timeDelta,
	}, level+1)
	if err != nil {
		return nil, err
	}

	return append(nodeResult, append(psetsLeft, psetsRight...)...), nil
}
