package bitcointree

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	ErrInvalidPoolTransaction        = errors.New("invalid pool transaction")
	ErrInvalidPoolTransactionOutputs = errors.New("invalid number of outputs in pool transaction")
	ErrEmptyTree                     = errors.New("empty congestion tree")
	ErrInvalidRootLevel              = errors.New("root level must have only one node")
	ErrNoLeaves                      = errors.New("no leaves in the tree")
	ErrNodeTransactionEmpty          = errors.New("node transaction is empty")
	ErrNodeTxidEmpty                 = errors.New("node txid is empty")
	ErrNodeParentTxidEmpty           = errors.New("node parent txid is empty")
	ErrNodeTxidDifferent             = errors.New("node txid differs from node transaction")
	ErrNumberOfInputs                = errors.New("node transaction should have only one input")
	ErrNumberOfOutputs               = errors.New("node transaction should have only three or two outputs")
	ErrParentTxidInput               = errors.New("parent txid should be the input of the node transaction")
	ErrNumberOfChildren              = errors.New("node branch transaction should have two children")
	ErrLeafChildren                  = errors.New("leaf node should have max 1 child")
	ErrInvalidChildTxid              = errors.New("invalid child txid")
	ErrNumberOfTapscripts            = errors.New("input should have 1 tapscript leaf")
	ErrInternalKey                   = errors.New("invalid taproot internal key")
	ErrInvalidTaprootScript          = errors.New("invalid taproot script")
	ErrInvalidControlBlock           = errors.New("invalid control block")
	ErrInvalidTaprootScriptLen       = errors.New("invalid taproot script length (expected 32 bytes)")
	ErrInvalidLeafTaprootScript      = errors.New("invalid leaf taproot script")
	ErrInvalidAmount                 = errors.New("children amount is different from parent amount")
	ErrInvalidSweepSequence          = errors.New("invalid sweep sequence")
	ErrInvalidASP                    = errors.New("invalid ASP")
	ErrMissingFeeOutput              = errors.New("missing fee output")
	ErrInvalidLeftOutput             = errors.New("invalid left output")
	ErrInvalidRightOutput            = errors.New("invalid right output")
	ErrMissingSweepTapscript         = errors.New("missing sweep tapscript")
	ErrInvalidLeaf                   = errors.New("leaf node shouldn't have children")
	ErrWrongPoolTxID                 = errors.New("root input should be the pool tx outpoint")
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

// ValidateCongestionTree checks if the given congestion tree is valid
// poolTxID & poolTxIndex & poolTxAmount are used to validate the root input outpoint
// aspPublicKey & roundLifetime are used to validate the sweep tapscript leaves
// besides that, the function validates:
// - the number of nodes
// - the number of leaves
// - children coherence with parent
// - every control block and taproot output scripts
// - input and output amounts
func ValidateCongestionTree(
	tree tree.CongestionTree, poolTx string, aspPublicKey *secp256k1.PublicKey,
	roundLifetime int64, cosigners []*secp256k1.PublicKey, minRelayFee int64,
) error {
	poolTransaction, err := psbt.NewFromRawBytes(strings.NewReader(poolTx), true)
	if err != nil {
		return ErrInvalidPoolTransaction
	}

	if len(poolTransaction.Outputs) < sharedOutputIndex+1 {
		return ErrInvalidPoolTransactionOutputs
	}

	poolTxAmount := poolTransaction.UnsignedTx.TxOut[sharedOutputIndex].Value

	nbNodes := tree.NumberOfNodes()
	if nbNodes == 0 {
		return ErrEmptyTree
	}

	if len(tree[0]) != 1 {
		return ErrInvalidRootLevel
	}

	// check that root input is connected to the pool tx
	rootPsetB64 := tree[0][0].Tx
	rootPset, err := psbt.NewFromRawBytes(strings.NewReader(rootPsetB64), true)
	if err != nil {
		return fmt.Errorf("invalid root transaction: %w", err)
	}

	if len(rootPset.Inputs) != 1 {
		return ErrNumberOfInputs
	}

	rootInput := rootPset.UnsignedTx.TxIn[0]
	if chainhash.Hash(rootInput.PreviousOutPoint.Hash).String() != poolTransaction.UnsignedTx.TxHash().String() ||
		rootInput.PreviousOutPoint.Index != sharedOutputIndex {
		return ErrWrongPoolTxID
	}

	sumRootValue := minRelayFee
	for _, output := range rootPset.UnsignedTx.TxOut {
		sumRootValue += output.Value
	}

	if sumRootValue != poolTxAmount {
		return ErrInvalidAmount
	}

	if len(tree.Leaves()) == 0 {
		return ErrNoLeaves
	}

	sweepClosure := &CSVSigClosure{
		Seconds: uint(roundLifetime),
		Pubkey:  aspPublicKey,
	}

	sweepLeaf, err := sweepClosure.Leaf()
	if err != nil {
		return err
	}

	tapTree := txscript.AssembleTaprootScriptTree(*sweepLeaf)
	root := tapTree.RootNode.TapHash()

	signers := append(cosigners, aspPublicKey)
	aggregatedKey, err := aggregateKeys(signers, root[:])
	if err != nil {
		return err
	}

	// iterates over all the nodes of the tree
	for _, level := range tree {
		for _, node := range level {
			if err := validateNodeTransaction(
				node, tree, aggregatedKey, minRelayFee,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateNodeTransaction(
	node tree.Node, tree tree.CongestionTree,
	expectedAggregatedKey *musig2.AggregateKey, minRelayFee int64,
) error {
	if node.Tx == "" {
		return ErrNodeTransactionEmpty
	}

	if node.Txid == "" {
		return ErrNodeTxidEmpty
	}

	if node.ParentTxid == "" {
		return ErrNodeParentTxidEmpty
	}

	decodedPset, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
	if err != nil {
		return fmt.Errorf("invalid node transaction: %w", err)
	}

	if decodedPset.UnsignedTx.TxHash().String() != node.Txid {
		return ErrNodeTxidDifferent
	}

	if len(decodedPset.Inputs) != 1 {
		return ErrNumberOfInputs
	}

	input := decodedPset.Inputs[0]
	if len(input.TaprootLeafScript) != 1 {
		return ErrNumberOfTapscripts
	}

	prevTxid := decodedPset.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String()
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

		parentOutput := decodedPset.UnsignedTx.TxOut[childIndex]
		previousScriptKey := parentOutput.PkScript[2:]
		if len(previousScriptKey) != 32 {
			return ErrInvalidTaprootScript
		}

		inputData := decodedPset.Inputs[0]

		inputTapInternalKey, err := schnorr.ParsePubKey(inputData.TaprootInternalKey)
		if err != nil {
			return fmt.Errorf("invalid internal key: %w", err)
		}

		if !bytes.Equal(inputData.TaprootInternalKey, schnorr.SerializePubKey(expectedAggregatedKey.PreTweakedKey)) {
			return ErrInternalKey
		}

		inputTapLeaf := inputData.TaprootLeafScript[0]

		ctrlBlock, err := txscript.ParseControlBlock(inputTapLeaf.ControlBlock)
		if err != nil {
			return ErrInvalidControlBlock
		}

		rootHash := ctrlBlock.RootHash(inputTapLeaf.Script)
		tapKey := txscript.ComputeTaprootOutputKey(inputTapInternalKey, rootHash)

		if !bytes.Equal(schnorr.SerializePubKey(tapKey), schnorr.SerializePubKey(expectedAggregatedKey.FinalKey)) {
			return ErrInvalidTaprootScript
		}

		sumChildAmount := minRelayFee
		for _, output := range childTx.UnsignedTx.TxOut {
			sumChildAmount += output.Value
		}

		if sumChildAmount != parentOutput.Value {
			return ErrInvalidAmount
		}
	}

	return nil
}
