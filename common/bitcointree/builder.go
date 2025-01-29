package bitcointree

import (
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// CraftSharedOutput returns the taproot script and the amount of the root shared output of a vtxo tree
func CraftSharedOutput(
	receivers []tree.VtxoLeaf,
	feeSatsPerNode uint64,
	sweepTapTreeRoot []byte,
) ([]byte, int64, error) {
	root, err := createRootNode(receivers, feeSatsPerNode, sweepTapTreeRoot)
	if err != nil {
		return nil, 0, err
	}

	amount := root.getAmount() + int64(feeSatsPerNode)

	aggregatedKey, err := AggregateKeys(root.getCosigners(), sweepTapTreeRoot)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to aggregate keys: %w", err)
	}

	scriptPubkey, err := common.P2TRScript(aggregatedKey.FinalKey)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create script pubkey: %w", err)
	}

	return scriptPubkey, amount, nil
}

// BuildVtxoTree creates all the tree's transactions and returns the vtxo tree
func BuildVtxoTree(
	initialInput *wire.OutPoint,
	receivers []tree.VtxoLeaf,
	feeSatsPerNode uint64,
	sweepTapTreeRoot []byte,
	vtxoTreeExpiry common.RelativeLocktime,
) (tree.VtxoTree, error) {
	root, err := createRootNode(receivers, feeSatsPerNode, sweepTapTreeRoot)
	if err != nil {
		return nil, err
	}

	vtxoTree := make(tree.VtxoTree, 0)

	ins := []*wire.OutPoint{initialInput}
	nodes := []node{root}

	for len(nodes) > 0 {
		nextNodes := make([]node, 0)
		nextInputsArgs := make([]*wire.OutPoint, 0)

		treeLevel := make([]tree.Node, 0)

		for i, node := range nodes {
			treeNode, err := getTreeNode(node, ins[i], vtxoTreeExpiry)
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

		vtxoTree = append(vtxoTree, treeLevel)
		nodes = append([]node{}, nextNodes...)
		ins = append([]*wire.OutPoint{}, nextInputsArgs...)
	}

	return vtxoTree, nil
}

type node interface {
	getAmount() int64 // returns the input amount of the node = sum of all receivers' amounts + fees
	getOutputs() ([]*wire.TxOut, error)
	getChildren() []node
	getCosigners() []*secp256k1.PublicKey
}

type leaf struct {
	amount     int64
	pkScript   []byte
	cosigners  []*secp256k1.PublicKey
	signerType tree.SigningType
}

type branch struct {
	cosigners []*secp256k1.PublicKey
	pkScript  []byte
	children  []node
	feeAmount int64
}

func (b *branch) getCosigners() []*secp256k1.PublicKey {
	return b.cosigners
}

func (l *leaf) getCosigners() []*secp256k1.PublicKey {
	return l.cosigners
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
	return []*wire.TxOut{
		{
			Value:    l.amount,
			PkScript: l.pkScript,
		},
	}, nil
}

func (b *branch) getOutputs() ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0)

	for _, child := range b.children {
		outputs = append(outputs, &wire.TxOut{
			Value:    child.getAmount() + b.feeAmount,
			PkScript: b.pkScript,
		})
	}

	return outputs, nil
}

func getTreeNode(
	n node,
	input *wire.OutPoint,
	vtxoTreeExpiry common.RelativeLocktime,
) (tree.Node, error) {
	partialTx, err := getTx(n, input, vtxoTreeExpiry)
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
	vtxoTreeExpiry common.RelativeLocktime,
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

	for _, cosigner := range n.getCosigners() {
		if err := AddCosignerKey(0, tx, cosigner); err != nil {
			return nil, err
		}
	}

	if err := AddVtxoTreeExpiry(0, tx, vtxoTreeExpiry); err != nil {
		return nil, err
	}

	return tx, nil
}

func createRootNode(
	receivers []tree.VtxoLeaf,
	feeSatsPerNode uint64,
	sweepTapTreeRoot []byte,
) (root node, err error) {
	if len(receivers) == 0 {
		return nil, fmt.Errorf("no receivers provided")
	}

	cosignersALL := make([]*secp256k1.PublicKey, 0)
	for _, r := range receivers {
		if r.Musig2Data == nil {
			return nil, fmt.Errorf("missing musig2 data for receiver %s", r.PubKey)
		}

		if r.Musig2Data.SigningType != tree.SignAll {
			continue
		}

		if len(r.Musig2Data.CosignersPublicKeys) == 0 {
			return nil, fmt.Errorf("missing cosigners public keys for receiver %s", r.PubKey)
		}

		for _, cosigner := range r.Musig2Data.CosignersPublicKeys {
			pubkeyBytes, err := hex.DecodeString(cosigner)
			if err != nil {
				return nil, err
			}

			pubkey, err := secp256k1.ParsePubKey(pubkeyBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse cosigner pubkey: %w", err)
			}
			cosignersALL = append(cosignersALL, pubkey)
		}
	}

	nodes := make([]node, 0, len(receivers))
	for _, r := range receivers {
		pubkeyBytes, err := hex.DecodeString(r.PubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode cosigner pubkey: %w", err)
		}

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse vtxo script pubkey: %w", err)
		}

		pkScript, err := common.P2TRScript(pubkey)
		if err != nil {
			return nil, fmt.Errorf("failed to create script pub key: %w", err)
		}

		cosigners := make([]*secp256k1.PublicKey, 0)

		switch r.Musig2Data.SigningType {
		case tree.SignBranch:
			for _, cosigner := range r.Musig2Data.CosignersPublicKeys {
				pubkeyBytes, err := hex.DecodeString(cosigner)
				if err != nil {
					return nil, fmt.Errorf("failed to decode cosigner pubkey: %w", err)
				}

				pubkey, err := secp256k1.ParsePubKey(pubkeyBytes)
				if err != nil {
					return nil, fmt.Errorf("failed to parse cosigner pubkey: %w", err)
				}

				cosigners = append(cosigners, pubkey)
			}
		case tree.SignAll:
			cosigners = cosignersALL
		}

		if len(cosigners) == 0 {
			return nil, fmt.Errorf("no cosigners for %s", r.PubKey)
		}

		leafNode := &leaf{
			amount:     int64(r.Amount),
			pkScript:   pkScript,
			cosigners:  cosigners,
			signerType: r.Musig2Data.SigningType,
		}
		nodes = append(nodes, leafNode)
	}

	for len(nodes) > 1 {
		nodes, err = createUpperLevel(nodes, int64(feeSatsPerNode), sweepTapTreeRoot)
		if err != nil {
			return nil, fmt.Errorf("failed to vtxo tree: %w", err)
		}
	}

	return nodes[0], nil
}

func createUpperLevel(nodes []node, feeAmount int64, tapTreeRoot []byte) ([]node, error) {
	if len(nodes)%2 != 0 {
		last := nodes[len(nodes)-1]
		pairs, err := createUpperLevel(nodes[:len(nodes)-1], feeAmount, tapTreeRoot)
		if err != nil {
			return nil, err
		}

		return append(pairs, last), nil
	}

	pairs := make([]node, 0, len(nodes)/2)
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		right := nodes[i+1]

		cosigners := append(left.getCosigners(), right.getCosigners()...)

		aggregatedKey, err := AggregateKeys(cosigners, tapTreeRoot)
		if err != nil {
			return nil, err
		}

		pkScript, err := common.P2TRScript(aggregatedKey.FinalKey)
		if err != nil {
			return nil, err
		}

		branchNode := &branch{
			pkScript:  pkScript,
			cosigners: cosigners,
			feeAmount: feeAmount,
			children:  []node{left, right},
		}

		pairs = append(pairs, branchNode)
	}
	return pairs, nil
}
