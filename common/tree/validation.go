package tree

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
)

var (
	ErrInvalidRoundTx           = fmt.Errorf("invalid round transaction")
	ErrInvalidRoundTxOutputs    = fmt.Errorf("invalid number of outputs in round transaction")
	ErrEmptyTree                = fmt.Errorf("empty vtxo tree")
	ErrInvalidRootLevel         = fmt.Errorf("root level must have only one node")
	ErrNoLeaves                 = fmt.Errorf("no leaves in the tree")
	ErrNodeTxEmpty              = fmt.Errorf("node transaction is empty")
	ErrNodeTxidEmpty            = fmt.Errorf("node txid is empty")
	ErrNodeParentTxidEmpty      = fmt.Errorf("node parent txid is empty")
	ErrNodeTxidDifferent        = fmt.Errorf("node txid differs from node transaction")
	ErrNumberOfInputs           = fmt.Errorf("node transaction should have only one input")
	ErrNumberOfOutputs          = fmt.Errorf("node transaction should have only three or two outputs")
	ErrParentTxidInput          = fmt.Errorf("parent txid should be the input of the node transaction")
	ErrNumberOfChildren         = fmt.Errorf("node branch transaction should have two children")
	ErrLeafChildren             = fmt.Errorf("leaf node should have max 1 child")
	ErrInvalidChildTxid         = fmt.Errorf("invalid child txid")
	ErrNumberOfTapscripts       = fmt.Errorf("input should have 1 tapscript leaf")
	ErrInternalKey              = fmt.Errorf("invalid taproot internal key")
	ErrInvalidTaprootScript     = fmt.Errorf("invalid taproot script")
	ErrInvalidTaprootScriptLen  = fmt.Errorf("invalid taproot script length (expected 32 bytes)")
	ErrInvalidLeafTaprootScript = fmt.Errorf("invalid leaf taproot script")
	ErrInvalidAmount            = fmt.Errorf("children amount is different from parent amount")
	ErrInvalidAsset             = errors.New("invalid output asset")
	ErrInvalidSweepSequence     = fmt.Errorf("invalid sweep sequence")
	ErrInvalidServer            = fmt.Errorf("invalid server")
	ErrMissingFeeOutput         = fmt.Errorf("missing fee output")
	ErrInvalidLeftOutput        = fmt.Errorf("invalid left output")
	ErrInvalidRightOutput       = fmt.Errorf("invalid right output")
	ErrMissingSweepTapscript    = fmt.Errorf("missing sweep tapscript")
	ErrMissingBranchTapscript   = errors.New("missing branch tapscript")
	ErrInvalidLeaf              = fmt.Errorf("leaf node shouldn't have children")
	ErrWrongRoundTxid           = fmt.Errorf("the input of the tree root is not the round tx's shared output")
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
	tree VtxoTree, roundTx string, serverPubkey *secp256k1.PublicKey,
	vtxoTreeExpiry common.RelativeLocktime,
) error {
	roundTransaction, err := psetv2.NewPsetFromBase64(roundTx)
	if err != nil {
		return ErrInvalidRoundTx
	}

	if len(roundTransaction.Outputs) < sharedOutputIndex+1 {
		return ErrInvalidRoundTxOutputs
	}

	roundTxAmount := roundTransaction.Outputs[sharedOutputIndex].Value

	utx, err := roundTransaction.UnsignedTx()
	if err != nil {
		return ErrInvalidRoundTx
	}

	roundTxid := utx.TxHash().String()

	nbNodes := tree.NumberOfNodes()
	if nbNodes == 0 {
		return ErrEmptyTree
	}

	if len(tree[0]) != 1 {
		return ErrInvalidRootLevel
	}

	// check that root input is connected to the round tx
	rootPsetB64 := tree[0][0].Tx
	rootPset, err := psetv2.NewPsetFromBase64(rootPsetB64)
	if err != nil {
		return fmt.Errorf("invalid root transaction: %w", err)
	}

	if len(rootPset.Inputs) != 1 {
		return ErrNumberOfInputs
	}

	rootInput := rootPset.Inputs[0]
	if chainhash.Hash(rootInput.PreviousTxid).String() != roundTxid ||
		rootInput.PreviousTxIndex != sharedOutputIndex {
		return ErrWrongRoundTxid
	}

	sumRootValue := uint64(0)
	for _, output := range rootPset.Outputs {
		sumRootValue += output.Value
	}

	if sumRootValue != roundTxAmount {
		return ErrInvalidAmount
	}

	if len(tree.Leaves()) == 0 {
		return ErrNoLeaves
	}

	// iterates over all the nodes of the tree
	for _, level := range tree {
		for _, node := range level {
			if err := validateNodeTransaction(
				node, tree, UnspendableKey(), serverPubkey, vtxoTreeExpiry,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateNodeTransaction(
	node Node, tree VtxoTree,
	expectedInternalKey, expectedServerPubkey *secp256k1.PublicKey,
	expectedVtxoTreeExpiry common.RelativeLocktime,
) error {
	if node.Tx == "" {
		return ErrNodeTxEmpty
	}

	if node.Txid == "" {
		return ErrNodeTxidEmpty
	}

	if node.ParentTxid == "" {
		return ErrNodeParentTxidEmpty
	}

	decodedPset, err := psetv2.NewPsetFromBase64(node.Tx)
	if err != nil {
		return fmt.Errorf("invalid node transaction: %w", err)
	}

	utx, err := decodedPset.UnsignedTx()
	if err != nil {
		return fmt.Errorf("invalid node transaction: %w", err)
	}

	if utx.TxHash().String() != node.Txid {
		return ErrNodeTxidDifferent
	}

	if len(decodedPset.Inputs) != 1 {
		return ErrNumberOfInputs
	}

	input := decodedPset.Inputs[0]
	if len(input.TapLeafScript) != 2 {
		return ErrNumberOfTapscripts
	}

	prevTxid := chainhash.Hash(decodedPset.Inputs[0].PreviousTxid).String()
	if prevTxid != node.ParentTxid {
		return ErrParentTxidInput
	}

	feeOutput := decodedPset.Outputs[len(decodedPset.Outputs)-1]
	if len(feeOutput.Script) != 0 {
		return ErrMissingFeeOutput
	}

	children := tree.Children(node.Txid)

	if node.Leaf && len(children) >= 1 {
		return ErrLeafChildren
	}

	for childIndex, child := range children {
		childTx, err := psetv2.NewPsetFromBase64(child.Tx)
		if err != nil {
			return fmt.Errorf("invalid child transaction: %w", err)
		}

		parentOutput := decodedPset.Outputs[childIndex]
		previousScriptKey := parentOutput.Script[2:]
		if len(previousScriptKey) != 32 {
			return ErrInvalidTaprootScript
		}

		sweepLeafFound := false
		branchLeafFound := false

		for _, tapLeaf := range childTx.Inputs[0].TapLeafScript {
			key := tapLeaf.ControlBlock.InternalKey
			if !key.IsEqual(expectedInternalKey) {
				return ErrInternalKey
			}

			rootHash := tapLeaf.ControlBlock.RootHash(tapLeaf.Script)
			outputScript := taproot.ComputeTaprootOutputKey(key, rootHash)

			if !bytes.Equal(
				schnorr.SerializePubKey(outputScript), previousScriptKey,
			) {
				return ErrInvalidTaprootScript
			}

			closure, err := DecodeClosure(tapLeaf.Script)
			if err != nil {
				continue
			}

			switch c := closure.(type) {
			case *CSVMultisigClosure:
				isServer := len(c.MultisigClosure.PubKeys) == 1 && bytes.Equal(
					schnorr.SerializePubKey(c.MultisigClosure.PubKeys[0]),
					schnorr.SerializePubKey(expectedServerPubkey),
				)

				isSweepDelay := c.Locktime == expectedVtxoTreeExpiry

				if isServer && !isSweepDelay {
					return ErrInvalidSweepSequence
				}

				if isSweepDelay && !isServer {
					return ErrInvalidServer
				}

				if isServer && isSweepDelay {
					sweepLeafFound = true
				}
			case *UnrollClosure:
				branchLeafFound = true

				// check outputs
				nbOuts := len(childTx.Outputs)
				if c.LeftKey != nil && c.RightKey != nil {
					if nbOuts != 3 {
						return ErrNumberOfOutputs
					}
				} else {
					if nbOuts != 2 {
						return ErrNumberOfOutputs
					}
				}

				leftWitnessProgram := childTx.Outputs[0].Script[2:]
				leftOutputAmount := childTx.Outputs[0].Value

				if !bytes.Equal(
					leftWitnessProgram, schnorr.SerializePubKey(c.LeftKey),
				) {
					return ErrInvalidLeftOutput
				}

				if c.RightKey == nil {
					inputAmount := parentOutput.Value
					if leftOutputAmount != inputAmount-c.MinRelayFee {
						return ErrInvalidLeftOutput
					}
				} else {
					if c.LeftAmount != leftOutputAmount {
						return ErrInvalidLeftOutput
					}

					rightWitnessProgram := childTx.Outputs[1].Script[2:]
					rightOutputAmount := childTx.Outputs[1].Value

					if !bytes.Equal(
						rightWitnessProgram, schnorr.SerializePubKey(c.RightKey),
					) {
						return ErrInvalidRightOutput
					}

					if c.RightAmount != rightOutputAmount {
						return ErrInvalidRightOutput
					}
				}

			default:
				continue
			}
		}

		if !sweepLeafFound {
			return ErrMissingSweepTapscript
		}

		if !branchLeafFound {
			return ErrMissingBranchTapscript
		}

		sumChildAmount := uint64(0)
		for _, output := range childTx.Outputs {
			sumChildAmount += output.Value
			if !bytes.Equal(output.Asset, parentOutput.Asset) {
				return ErrInvalidAsset
			}
		}

		if sumChildAmount != parentOutput.Value {
			return ErrInvalidAmount
		}
	}

	return nil
}
