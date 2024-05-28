package bitcointree

import (
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// CraftSharedOutput returns the taproot script and the amount of the initial root output
func CraftSharedOutput(
	cosigners []*secp256k1.PublicKey, aspPubkey *secp256k1.PublicKey, receivers []Receiver,
	feeSatsPerNode uint64, roundLifetime, unilateralExitDelay int64,
) ([]byte, int64, error) {
	aggregatedKey, _, err := createAggregatedKeyWithSweep(
		cosigners, aspPubkey, roundLifetime,
	)
	if err != nil {
		return nil, 0, err
	}

	root, err := createRootNode(aggregatedKey, aspPubkey, receivers, feeSatsPerNode, unilateralExitDelay)
	if err != nil {
		return nil, 0, err
	}

	amount := root.getAmount() + int64(feeSatsPerNode)

	scriptPubKey, err := taprootOutputScript(aggregatedKey.FinalKey)
	if err != nil {
		return nil, 0, err
	}

	return scriptPubKey, amount, err
}

// CraftCongestionTree creates all the tree's transactions
func CraftCongestionTree(
	initialInput *wire.OutPoint, cosigners []*secp256k1.PublicKey, aspPubkey *secp256k1.PublicKey, receivers []Receiver,
	feeSatsPerNode uint64, roundLifetime, unilateralExitDelay int64,
) (tree.CongestionTree, error) {
	aggregatedKey, sweepTapLeaf, err := createAggregatedKeyWithSweep(
		cosigners, aspPubkey, roundLifetime,
	)
	if err != nil {
		return nil, err
	}

	root, err := createRootNode(aggregatedKey, aspPubkey, receivers, feeSatsPerNode, unilateralExitDelay)
	if err != nil {
		return nil, err
	}

	congestionTree := make(tree.CongestionTree, 0)

	ins := []*wire.OutPoint{initialInput}
	nodes := []node{root}

	for len(nodes) > 0 {
		nextNodes := make([]node, 0)
		nextInputsArgs := make([]*wire.OutPoint, 0)

		treeLevel := make([]tree.Node, 0)

		for i, node := range nodes {
			treeNode, err := getTreeNode(node, ins[i], schnorr.SerializePubKey(aggregatedKey.PreTweakedKey), sweepTapLeaf)
			if err != nil {
				return nil, err
			}

			nodeTxHash, err := chainhash.NewHashFromStr(treeNode.Txid)
			if err != nil {
				return nil, err
			}

			treeLevel = append(treeLevel, treeNode)

			children := node.getChildren()

			for i, child := range children {
				nextNodes = append(nextNodes, child)

				nextInputsArgs = append(nextInputsArgs, &wire.OutPoint{
					Hash:  *nodeTxHash,
					Index: uint32(i),
				})
			}
		}

		congestionTree = append(congestionTree, treeLevel)
		nodes = append([]node{}, nextNodes...)
		ins = append([]*wire.OutPoint{}, nextInputsArgs...)
	}

	return congestionTree, nil
}

type node interface {
	getAmount() int64 // returns the input amount of the node = sum of all receivers' amounts + fees
	getOutputs() ([]*wire.TxOut, error)
	getChildren() []node
}

type leaf struct {
	aspKey    *secp256k1.PublicKey
	vtxoKey   *secp256k1.PublicKey
	exitDelay int64
	amount    int64
}

type branch struct {
	aggregatedKey *musig2.AggregateKey
	children      []node
	feeAmount     int64
}

func (b *branch) getChildren() []node {
	return b.children
}

func (l *leaf) getChildren() []node {
	return []node{}
}

func (b *branch) getAmount() int64 {
	amount := int64(0)
	for _, child := range b.children {
		amount += child.getAmount()
		amount += b.feeAmount
	}

	return amount
}

func (l *leaf) getAmount() int64 {
	return l.amount
}

func (l *leaf) getOutputs() ([]*wire.TxOut, error) {
	redeemClosure := &CSVSigClosure{
		Pubkey:  l.vtxoKey,
		Seconds: uint(l.exitDelay),
	}

	redeemLeaf, err := redeemClosure.Leaf()
	if err != nil {
		return nil, err
	}

	forfeitClosure := &ForfeitClosure{
		Pubkey:    l.vtxoKey,
		AspPubkey: l.aspKey,
	}

	forfeitLeaf, err := forfeitClosure.Leaf()
	if err != nil {
		return nil, err
	}

	leafTaprootTree := txscript.AssembleTaprootScriptTree(
		*redeemLeaf, *forfeitLeaf,
	)
	root := leafTaprootTree.RootNode.TapHash()

	taprootKey := txscript.ComputeTaprootOutputKey(
		UnspendableKey(),
		root[:],
	)

	script, err := taprootOutputScript(taprootKey)
	if err != nil {
		return nil, err
	}

	output := &wire.TxOut{
		Value:    l.amount,
		PkScript: script,
	}

	return []*wire.TxOut{output}, nil
}

func (b *branch) getOutputs() ([]*wire.TxOut, error) {
	sharedOutputScript, err := taprootOutputScript(b.aggregatedKey.FinalKey)
	if err != nil {
		return nil, err
	}

	outputs := make([]*wire.TxOut, 0)

	for _, child := range b.children {
		outputs = append(outputs, &wire.TxOut{
			Value:    child.getAmount() + b.feeAmount,
			PkScript: sharedOutputScript,
		})
	}

	return outputs, nil
}

func getTreeNode(
	n node,
	input *wire.OutPoint,
	inputTapInternalKey []byte,
	inputSweepTapLeaf *psbt.TaprootTapLeafScript,
) (tree.Node, error) {
	partialTx, err := getTx(n, input, inputTapInternalKey, inputSweepTapLeaf)
	if err != nil {
		return tree.Node{}, err
	}

	txid := partialTx.UnsignedTx.TxHash().String()

	tx, err := partialTx.B64Encode()
	if err != nil {
		return tree.Node{}, err
	}

	return tree.Node{
		Txid:       txid,
		Tx:         tx,
		ParentTxid: input.Hash.String(),
		Leaf:       len(n.getChildren()) == 0,
	}, nil
}

func getTx(
	n node,
	input *wire.OutPoint,
	inputTapInternalKey []byte,
	inputSweepTapLeaf *psbt.TaprootTapLeafScript,
) (*psbt.Packet, error) {
	outputs, err := n.getOutputs()
	if err != nil {
		return nil, err
	}

	tx, err := psbt.New([]*wire.OutPoint{input}, outputs, 2, 0, []uint32{wire.MaxTxInSequenceNum})
	if err != nil {
		return nil, err
	}

	updater, err := psbt.NewUpdater(tx)
	if err != nil {
		return nil, err
	}

	if err := updater.AddInSighashType(0, int(txscript.SigHashDefault)); err != nil {
		return nil, err
	}

	tx.Inputs[0].TaprootInternalKey = inputTapInternalKey
	tx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{inputSweepTapLeaf}

	return tx, nil
}

func createRootNode(
	aggregatedKey *musig2.AggregateKey, aspPubkey *secp256k1.PublicKey, receivers []Receiver,
	feeSatsPerNode uint64, unilateralExitDelay int64,
) (root node, err error) {
	if len(receivers) == 0 {
		return nil, fmt.Errorf("no receivers provided")
	}

	nodes := make([]node, 0, len(receivers))
	for _, r := range receivers {
		pubkeyBytes, err := hex.DecodeString(r.Pubkey)
		if err != nil {
			return nil, err
		}

		receiverKey, err := secp256k1.ParsePubKey(pubkeyBytes)
		if err != nil {
			return nil, err
		}

		leafNode := &leaf{
			aspKey:    aspPubkey,
			vtxoKey:   receiverKey,
			exitDelay: unilateralExitDelay,
			amount:    int64(r.Amount),
		}
		nodes = append(nodes, leafNode)
	}

	for len(nodes) > 1 {
		nodes, err = createUpperLevel(nodes, aggregatedKey, int64(feeSatsPerNode))
		if err != nil {
			return
		}
	}

	return nodes[0], nil
}

func createAggregatedKeyWithSweep(
	cosigners []*secp256k1.PublicKey, aspPubkey *secp256k1.PublicKey, roundLifetime int64,
) (*musig2.AggregateKey, *psbt.TaprootTapLeafScript, error) {
	sweepClosure := &CSVSigClosure{
		Pubkey:  aspPubkey,
		Seconds: uint(roundLifetime),
	}

	sweepLeaf, err := sweepClosure.Leaf()
	if err != nil {
		return nil, nil, err
	}

	tapTree := txscript.AssembleTaprootScriptTree(*sweepLeaf)
	tapTreeRoot := tapTree.RootNode.TapHash()

	aggregatedKey, err := AggregateKeys(
		cosigners, tapTreeRoot[:],
	)
	if err != nil {
		return nil, nil, err
	}

	index := tapTree.LeafProofIndex[sweepLeaf.TapHash()]
	proof := tapTree.LeafMerkleProofs[index]

	controlBlock := proof.ToControlBlock(aggregatedKey.PreTweakedKey)
	controlBlockBytes, err := controlBlock.ToBytes()
	if err != nil {
		return nil, nil, err
	}

	tapLeaf := &psbt.TaprootTapLeafScript{
		ControlBlock: controlBlockBytes,
		Script:       sweepLeaf.Script,
		LeafVersion:  sweepLeaf.LeafVersion,
	}

	return aggregatedKey, tapLeaf, nil
}

func createUpperLevel(nodes []node, aggregatedKey *musig2.AggregateKey, feeAmount int64) ([]node, error) {
	if len(nodes)%2 != 0 {
		last := nodes[len(nodes)-1]
		pairs, err := createUpperLevel(nodes[:len(nodes)-1], aggregatedKey, feeAmount)
		if err != nil {
			return nil, err
		}

		return append(pairs, last), nil
	}

	pairs := make([]node, 0, len(nodes)/2)
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		right := nodes[i+1]
		branchNode := &branch{
			aggregatedKey: aggregatedKey,
			feeAmount:     feeAmount,
			children:      []node{left, right},
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
