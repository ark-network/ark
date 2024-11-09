package bitcointree

import (
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
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
	cosigners []*secp256k1.PublicKey,
	aspPubkey *secp256k1.PublicKey,
	receivers []tree.VtxoLeaf,
	feeSatsPerNode,
	dustAmount uint64,
	roundLifetime int64,
) ([]byte, int64, error) {
	aggregatedKey, _, err := createAggregatedKeyWithSweep(
		cosigners, aspPubkey, roundLifetime,
	)
	if err != nil {
		return nil, 0, err
	}

	root, err := createRootNode(aggregatedKey, cosigners, receivers, feeSatsPerNode, dustAmount)
	if err != nil {
		return nil, 0, err
	}

	amount := root.getAmount() + int64(feeSatsPerNode)

	scriptPubKey, err := common.P2TRScript(aggregatedKey.FinalKey)
	if err != nil {
		return nil, 0, err
	}

	return scriptPubKey, amount, err
}

// CraftCongestionTree creates all the tree's transactions
func CraftCongestionTree(
	initialInput *wire.OutPoint,
	cosigners []*secp256k1.PublicKey,
	aspPubkey *secp256k1.PublicKey,
	receivers []tree.VtxoLeaf,
	feeSatsPerNode,
	dustAmount uint64,
	roundLifetime int64,
) (tree.CongestionTree, error) {
	aggregatedKey, sweepTapLeaf, err := createAggregatedKeyWithSweep(
		cosigners, aspPubkey, roundLifetime,
	)
	if err != nil {
		return nil, err
	}

	root, err := createRootNode(aggregatedKey, cosigners, receivers, feeSatsPerNode, dustAmount)
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
			treeNode, err := getTreeNode(node, ins[i], schnorr.SerializePubKey(aggregatedKey.PreTweakedKey), sweepTapLeaf, cosigners)
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
	getTxVersion() int32
}

type leaf struct {
	amount     int64
	dustAmount int64
	pubkey     *secp256k1.PublicKey
}

type branch struct {
	aggregatedKey *musig2.AggregateKey
	cosigners     []*secp256k1.PublicKey
	children      []node
	feeAmount     int64
}

func (b *branch) getTxVersion() int32 {
	return 2
}

func (l *leaf) getTxVersion() int32 {
	return 3
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
		if child.getTxVersion() == 2 {
			amount += b.feeAmount
		}
	}

	return amount
}

func (l *leaf) getAmount() int64 {
	return l.amount
}

func (l *leaf) getOutputs() ([]*wire.TxOut, error) {
	script, err := common.P2TRScript(l.pubkey)
	if err != nil {
		return nil, err
	}

	vtxoOutput := &wire.TxOut{
		Value:    l.amount,
		PkScript: script,
	}

	anchorOutput := &wire.TxOut{
		Value:    0,
		PkScript: ANCHOR_PKSCRIPT,
	}

	return []*wire.TxOut{vtxoOutput, anchorOutput}, nil
}

func (b *branch) getOutputs() ([]*wire.TxOut, error) {
	sharedOutputScript, err := common.P2TRScript(b.aggregatedKey.FinalKey)
	if err != nil {
		return nil, err
	}

	outputs := make([]*wire.TxOut, 0)

	for _, child := range b.children {
		value := child.getAmount()
		if child.getTxVersion() == 2 {
			value += b.feeAmount
		}

		outputs = append(outputs, &wire.TxOut{
			Value:    value,
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
	cosigners []*secp256k1.PublicKey,
) (tree.Node, error) {
	partialTx, err := getTx(n, input, inputTapInternalKey, inputSweepTapLeaf, cosigners)
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

// getTx returns the psbt associated with the node
// the psbt contains the inputs of the parent and the outputs of the children (or VTXOs if it's a leaf)
// it also contains the internal key used to "unroll" and the sweep tascript branch of the input
func getTx(
	n node,
	input *wire.OutPoint,
	inputTapInternalKey []byte,
	inputSweepTapLeaf *psbt.TaprootTapLeafScript,
	cosigners []*secp256k1.PublicKey,
) (*psbt.Packet, error) {
	outputs, err := n.getOutputs()
	if err != nil {
		return nil, err
	}

	tx, err := psbt.New(
		[]*wire.OutPoint{input},
		outputs,
		n.getTxVersion(),
		0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
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

	for _, cosigner := range cosigners {
		if err := AddCosignerKey(0, tx, cosigner); err != nil {
			return nil, err
		}
	}

	return tx, nil
}

func createRootNode(
	aggregatedKey *musig2.AggregateKey,
	cosigners []*secp256k1.PublicKey,
	receivers []tree.VtxoLeaf,
	feeSatsPerNode,
	dustAmount uint64,
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

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return nil, err
		}

		leafNode := &leaf{
			amount:     int64(r.Amount),
			dustAmount: int64(dustAmount),
			pubkey:     pubkey,
		}
		nodes = append(nodes, leafNode)
	}

	for len(nodes) > 1 {
		nodes, err = createUpperLevel(nodes, aggregatedKey, cosigners, int64(feeSatsPerNode))
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

func createUpperLevel(nodes []node, aggregatedKey *musig2.AggregateKey, cosigners []*secp256k1.PublicKey, feeAmount int64) ([]node, error) {
	if len(nodes)%2 != 0 {
		last := nodes[len(nodes)-1]
		pairs, err := createUpperLevel(nodes[:len(nodes)-1], aggregatedKey, cosigners, feeAmount)
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
			cosigners:     cosigners,
			feeAmount:     feeAmount,
			children:      []node{left, right},
		}

		pairs = append(pairs, branchNode)
	}
	return pairs, nil
}
