package bitcointree

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	ErrInvalidRoundTx             = fmt.Errorf("invalid round transaction")
	ErrInvalidRoundTxOutputs      = fmt.Errorf("invalid number of outputs in round transaction")
	ErrEmptyTree                  = fmt.Errorf("empty vtxo tree")
	ErrInvalidRootLevel           = fmt.Errorf("root level must have only one node")
	ErrNoLeaves                   = fmt.Errorf("no leaves in the tree")
	ErrNodeTxEmpty                = fmt.Errorf("node transaction is empty")
	ErrNodeTxidEmpty              = fmt.Errorf("node txid is empty")
	ErrNodeParentTxidEmpty        = fmt.Errorf("node parent txid is empty")
	ErrNodeTxidDifferent          = fmt.Errorf("node txid differs from node transaction")
	ErrNumberOfInputs             = fmt.Errorf("node transaction should have only one input")
	ErrNumberOfOutputs            = fmt.Errorf("node transaction should have only three or two outputs")
	ErrParentTxidInput            = fmt.Errorf("parent txid should be the input of the node transaction")
	ErrNumberOfChildren           = fmt.Errorf("node branch transaction should have two children")
	ErrLeafChildren               = fmt.Errorf("leaf node should have max 1 child")
	ErrInvalidChildTxid           = fmt.Errorf("invalid child txid")
	ErrInternalKey                = fmt.Errorf("invalid taproot internal key")
	ErrInvalidTaprootScript       = fmt.Errorf("invalid taproot script")
	ErrMissingCosignersPublicKeys = fmt.Errorf("missing cosigners public keys")
	ErrInvalidAmount              = fmt.Errorf("children amount is different from parent amount")
	ErrInvalidSweepSequence       = fmt.Errorf("invalid sweep sequence")
	ErrInvalidServer              = fmt.Errorf("invalid server")
	ErrMissingFeeOutput           = fmt.Errorf("missing fee output")
	ErrInvalidLeftOutput          = fmt.Errorf("invalid left output")
	ErrInvalidRightOutput         = fmt.Errorf("invalid right output")
	ErrMissingSweepTapscript      = fmt.Errorf("missing sweep tapscript")
	ErrInvalidLeaf                = fmt.Errorf("leaf node shouldn't have children")
	ErrWrongRoundTxid             = fmt.Errorf("the input of the tree root is not the round tx's shared output")
)

// 0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
var unspendablePoint = []byte{
	0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
	0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
}

const (
	sharedOutputIndex = 0
)

func UnspendableKey() *secp256k1.PublicKey {
	key, _ := secp256k1.ParsePubKey(unspendablePoint)
	return key
}

// ValidateVtxoTree checks if the given vtxo tree is valid
// roundTxid & roundTxIndex & roundTxAmount are used to validate the root input outpoint
// serverPubkey & vtxoTreeExpiry are used to validate the sweep tapscript leaves
// besides that, the function validates:
// - the number of nodes
// - the number of leaves
// - children coherence with parent
// - every control block and taproot output scripts
// - input and output amounts
func ValidateVtxoTree(
	vtxoTree tree.VtxoTree, roundTx string, serverPubkey *secp256k1.PublicKey, vtxoTreeExpiry common.RelativeLocktime,
) error {
	roundTransaction, err := psbt.NewFromRawBytes(strings.NewReader(roundTx), true)
	if err != nil {
		return ErrInvalidRoundTx
	}

	if len(roundTransaction.Outputs) < sharedOutputIndex+1 {
		return ErrInvalidRoundTxOutputs
	}

	roundTxAmount := roundTransaction.UnsignedTx.TxOut[sharedOutputIndex].Value

	nbNodes := vtxoTree.NumberOfNodes()
	if nbNodes == 0 {
		return ErrEmptyTree
	}

	if len(vtxoTree[0]) != 1 {
		return ErrInvalidRootLevel
	}

	// check that root input is connected to the round tx
	rootPsetB64 := vtxoTree[0][0].Tx
	rootPset, err := psbt.NewFromRawBytes(strings.NewReader(rootPsetB64), true)
	if err != nil {
		return fmt.Errorf("invalid root transaction: %w", err)
	}

	if len(rootPset.Inputs) != 1 {
		return ErrNumberOfInputs
	}

	rootInput := rootPset.UnsignedTx.TxIn[0]
	if chainhash.Hash(rootInput.PreviousOutPoint.Hash).String() != roundTransaction.UnsignedTx.TxHash().String() ||
		rootInput.PreviousOutPoint.Index != sharedOutputIndex {
		return ErrWrongRoundTxid
	}

	sumRootValue := int64(0)
	for _, output := range rootPset.UnsignedTx.TxOut {
		sumRootValue += output.Value
	}

	if sumRootValue >= roundTxAmount {
		return ErrInvalidAmount
	}

	if len(vtxoTree.Leaves()) == 0 {
		return ErrNoLeaves
	}

	sweepClosure := &tree.CSVMultisigClosure{
		MultisigClosure: tree.MultisigClosure{PubKeys: []*secp256k1.PublicKey{serverPubkey}},
		Locktime:        vtxoTreeExpiry,
	}

	sweepScript, err := sweepClosure.Script()
	if err != nil {
		return err
	}

	sweepLeaf := txscript.NewBaseTapLeaf(sweepScript)
	tapTree := txscript.AssembleTaprootScriptTree(sweepLeaf)
	root := tapTree.RootNode.TapHash()

	// iterates over all the nodes of the tree
	for _, level := range vtxoTree {
		for _, node := range level {
			if err := validateNodeTransaction(
				node, vtxoTree, root.CloneBytes(),
			); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateNodeTransaction(node tree.Node, tree tree.VtxoTree, tapTreeRoot []byte) error {
	if node.Tx == "" {
		return ErrNodeTxEmpty
	}

	if node.Txid == "" {
		return ErrNodeTxidEmpty
	}

	if node.ParentTxid == "" {
		return ErrNodeParentTxidEmpty
	}

	decodedPsbt, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
	if err != nil {
		return fmt.Errorf("invalid node transaction: %w", err)
	}

	if decodedPsbt.UnsignedTx.TxHash().String() != node.Txid {
		return ErrNodeTxidDifferent
	}

	if len(decodedPsbt.Inputs) != 1 {
		return ErrNumberOfInputs
	}

	prevTxid := decodedPsbt.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String()
	if prevTxid != node.ParentTxid {
		return ErrParentTxidInput
	}

	children := tree.Children(node.Txid)

	if node.Leaf && len(children) >= 1 {
		return ErrLeafChildren
	}

	for childIndex, child := range children {
		childTx, err := psbt.NewFromRawBytes(strings.NewReader(child.Tx), true)
		if err != nil {
			return fmt.Errorf("invalid child transaction: %w", err)
		}

		parentOutput := decodedPsbt.UnsignedTx.TxOut[childIndex]
		previousScriptKey := parentOutput.PkScript[2:]
		if len(previousScriptKey) != 32 {
			return ErrInvalidTaprootScript
		}

		cosigners, err := GetCosignerKeys(decodedPsbt.Inputs[0])
		if err != nil {
			return fmt.Errorf("unable to get cosigners keys: %w", err)
		}

		if len(cosigners) == 0 {
			return ErrMissingCosignersPublicKeys
		}

		aggregatedKey, err := AggregateKeys(cosigners, tapTreeRoot)
		if err != nil {
			return fmt.Errorf("unable to aggregate keys: %w", err)
		}

		if !bytes.Equal(schnorr.SerializePubKey(aggregatedKey.FinalKey), previousScriptKey) {
			return ErrInvalidTaprootScript
		}

		sumChildAmount := int64(0)
		for _, output := range childTx.UnsignedTx.TxOut {
			sumChildAmount += output.Value
		}

		if sumChildAmount >= parentOutput.Value {
			return ErrInvalidAmount
		}
	}

	return nil
}
