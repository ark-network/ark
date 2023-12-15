package txbuilder

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

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
	OP_INSPECTOUTPUTSCRIPTPUBKEY = 0xd1
	OP_INSPECTOUTPUTVALUE        = 0xcf
	OP_PUSHCURRENTINPUTINDEX     = 0xcd
	unspendablePoint             = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)

// the private method buildCongestionTree returns a function letting to plug in the pool transaction output as input of the tree's root node
type pluggableCongestionTree func(outpoint psetv2.InputArgs) (domain.CongestionTree, error)

// withOutput returns an introspection script that checks the script and the amount of the output at the given index
// verify will add an OP_EQUALVERIFY at the end of the script, otherwise it will add an OP_EQUAL
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

// checkSequenceVerifyScript without checksig
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

// checkSequenceVerifyScript + checksig
func sweepScript(pubkey *secp256k1.PublicKey, seconds uint) ([]byte, error) {
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

// decodeSweepScript returns the lifetime of the sweep script if it is valid
func decodeSweepScript(script []byte) (isSweepLeaf bool, lifetime uint) {
	checkSequenceVerifyOpcodeIndex := -1
	for i, op := range script {
		if op == txscript.OP_CHECKSEQUENCEVERIFY {
			checkSequenceVerifyOpcodeIndex = i
			break
		}
	}
	if checkSequenceVerifyOpcodeIndex == -1 {
		return false, 0
	}

	lifetime, err := common.BIP68Decode(script[:checkSequenceVerifyOpcodeIndex])
	if err != nil {
		return false, 0
	}

	return true, lifetime
}

// sweepTapLeaf returns a taproot leaf letting the owner of the key to spend the output after a given timeDelta
func sweepTapLeaf(sweepKey *secp256k1.PublicKey, lifetime uint) (*taproot.TapElementsLeaf, error) {
	sweepScript, err := sweepScript(sweepKey, lifetime)
	if err != nil {
		return nil, err
	}

	tapLeaf := taproot.NewBaseTapElementsLeaf(sweepScript)
	return &tapLeaf, nil
}

// forceSplitCoinTapLeaf returns a taproot leaf that enforces a split into two outputs
// each output (left and right) will have the given amount and the given taproot key as witness program
func forceSplitCoinTapLeaf(
	leftKey, rightKey *secp256k1.PublicKey, leftAmount, rightAmount uint32,
) taproot.TapElementsLeaf {
	nextScriptLeft := withOutput(0, schnorr.SerializePubKey(leftKey), leftAmount, true)
	nextScriptRight := withOutput(1, schnorr.SerializePubKey(rightKey), rightAmount, false)
	branchScript := append(nextScriptLeft, nextScriptRight...)
	return taproot.NewBaseTapElementsLeaf(branchScript)
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

// buildCongestionTree builder iteratively creates a binary tree of Pset from a set of receivers
// it returns a factory function creating a CongestionTree and the associated output script to be used in the pool transaction
func buildCongestionTree(
	net *network.Network,
	aspPublicKey *secp256k1.PublicKey,
	receivers []domain.Receiver,
	roundLifetime uint,
) (pluggableTree pluggableCongestionTree, sharedOutputScript []byte, err error) {
	unspendableKeyBytes, err := hex.DecodeString(unspendablePoint)
	if err != nil {
		return nil, nil, err
	}

	unspendableKey, err := secp256k1.ParsePubKey(unspendableKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	var nodes []*node

	for _, r := range receivers {
		nodes = append(nodes, newLeaf(net, unspendableKey, aspPublicKey, r, roundLifetime))
	}

	for len(nodes) > 1 {
		nodes, err = createTreeLevel(nodes)
		if err != nil {
			return nil, nil, err
		}
	}

	psets, err := nodes[0].psets(nil, 0)
	if err != nil {
		return nil, nil, err
	}

	// find the root
	var rootPset *psetv2.Pset
	for _, psetWithLevel := range psets {
		if psetWithLevel.level == 0 {
			rootPset = psetWithLevel.pset
			break
		}
	}

	// compute the shared output script
	sweepLeaf, err := sweepTapLeaf(aspPublicKey, roundLifetime)
	if err != nil {
		return nil, nil, err
	}

	leftOutput := rootPset.Outputs[0]
	rightOutput := rootPset.Outputs[1]

	leftWitnessProgram := leftOutput.Script[2:]
	leftKey, err := schnorr.ParsePubKey(leftWitnessProgram)
	if err != nil {
		return nil, nil, err
	}

	rightWitnessProgram := rightOutput.Script[2:]
	rightKey, err := schnorr.ParsePubKey(rightWitnessProgram)
	if err != nil {
		return nil, nil, err
	}

	goToTreeScript := forceSplitCoinTapLeaf(
		leftKey, rightKey, uint32(leftOutput.Value), uint32(rightOutput.Value),
	)

	taprootTree := taproot.AssembleTaprootScriptTree(goToTreeScript, *sweepLeaf)
	root := taprootTree.RootNode.TapHash()
	taprootKey := taproot.ComputeTaprootOutputKey(unspendableKey, root[:])
	outputScript, err := taprootOutputScript(taprootKey)
	if err != nil {
		return nil, nil, err
	}

	return func(outpoint psetv2.InputArgs) (domain.CongestionTree, error) {
		psets, err := nodes[0].psets(&psetArgs{
			input:       outpoint,
			taprootTree: taprootTree,
		}, 0)
		if err != nil {
			return nil, err
		}

		maxLevel := 0
		for _, p := range psets {
			if p.level > maxLevel {
				maxLevel = p.level
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
				Leaf:       psetWithLevel.leaf,
			})
		}
		return tree, nil
	}, outputScript, nil
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
	roundLifetime      uint

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
	roundLifetime uint,
) *node {
	return &node{
		sweepKey:           sweepKey,
		internalTaprootKey: internalKey,
		receivers:          []domain.Receiver{receiver},
		network:            network,
		roundLifetime:      roundLifetime,
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
		roundLifetime:      left.roundLifetime,
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

func (n *node) taprootKey() (*secp256k1.PublicKey, *taproot.IndexedElementsTapScriptTree, error) {
	if n._taprootKey != nil && n._taprootTree != nil {
		return n._taprootKey, n._taprootTree, nil
	}

	sweepTaprootLeaf, err := sweepTapLeaf(n.sweepKey, n.roundLifetime)
	if err != nil {
		return nil, nil, err
	}

	if n.isLeaf() {
		key, err := hex.DecodeString(n.receivers[0].Pubkey)
		if err != nil {
			return nil, nil, err
		}

		pubkey, err := secp256k1.ParsePubKey(key)
		if err != nil {
			return nil, nil, err
		}

		leafScript, err := checksigScript(pubkey)
		if err != nil {
			return nil, nil, err
		}

		leafTaprootLeaf := taproot.NewBaseTapElementsLeaf(leafScript)
		leafTaprootTree := taproot.AssembleTaprootScriptTree(leafTaprootLeaf, *sweepTaprootLeaf)
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

	branchTaprootLeaf := forceSplitCoinTapLeaf(
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

// use script & amount to create OutputArgs
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
func (n *node) pset(args *psetArgs) (*psetv2.Pset, error) {
	pset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return nil, err
	}

	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return nil, err
	}

	if args != nil {
		if err := addTaprootInput(updater, args.input, n.internalTaprootKey, args.taprootTree); err != nil {
			return nil, err
		}
	}

	if n.isLeaf() {
		output, err := n.output()
		if err != nil {
			return nil, err
		}

		err = updater.AddOutputs([]psetv2.OutputArgs{*output})
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

	err = updater.AddOutputs([]psetv2.OutputArgs{*outputLeft, *outputRight})
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

// create the node pset and all the psets of its children recursively, updating the input arg at each step
// the function stops when it reaches a leaf node
func (n *node) psets(inputArgs *psetArgs, level int) ([]psetWithLevel, error) {
	if inputArgs == nil && level != 0 {
		return nil, fmt.Errorf("only the first level must be pluggable")
	}

	pset, err := n.pset(inputArgs)
	if err != nil {
		return nil, err
	}

	nodeResult := []psetWithLevel{
		{pset, level, n.isLeaf()},
	}

	if n.isLeaf() {
		return nodeResult, nil
	}

	unsignedTx, err := pset.UnsignedTx()
	if err != nil {
		return nil, err
	}

	txID := unsignedTx.TxHash().String()

	_, taprootTree, err := n.taprootKey()
	if err != nil {
		return nil, err
	}

	psetsLeft, err := n.left.psets(&psetArgs{
		input: psetv2.InputArgs{
			Txid:    txID,
			TxIndex: 0,
		},
		taprootTree: taprootTree,
	}, level+1)
	if err != nil {
		return nil, err
	}

	psetsRight, err := n.right.psets(&psetArgs{
		input: psetv2.InputArgs{
			Txid:    txID,
			TxIndex: 1,
		},
		taprootTree: taprootTree,
	}, level+1)
	if err != nil {
		return nil, err
	}

	return append(nodeResult, append(psetsLeft, psetsRight...)...), nil
}
