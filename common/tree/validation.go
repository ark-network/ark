package tree

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
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
	ErrNumberOfTapscripts            = errors.New("input should have two tapscripts leaves")
	ErrInternalKey                   = errors.New("taproot internal key is not unspendable")
	ErrInvalidTaprootScript          = errors.New("invalid taproot script")
	ErrInvalidTaprootScriptLen       = errors.New("invalid taproot script length (expected 32 bytes)")
	ErrInvalidLeafTaprootScript      = errors.New("invalid leaf taproot script")
	ErrInvalidAmount                 = errors.New("children amount is different from parent amount")
	ErrInvalidAsset                  = errors.New("invalid output asset")
	ErrInvalidSweepSequence          = errors.New("invalid sweep sequence")
	ErrInvalidASP                    = errors.New("invalid ASP")
	ErrMissingFeeOutput              = errors.New("missing fee output")
	ErrInvalidLeftOutput             = errors.New("invalid left output")
	ErrInvalidRightOutput            = errors.New("invalid right output")
	ErrMissingSweepTapscript         = errors.New("missing sweep tapscript")
	ErrMissingBranchTapscript        = errors.New("missing branch tapscript")
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
// aspPublicKey & roundLifetimeSeconds are used to validate the sweep tapscript leaves
// besides that, the function validates:
// - the number of nodes
// - the number of leaves
// - children coherence with parent
// - every control block and taproot output scripts
// - input and output amounts
func ValidateCongestionTree(
	tree CongestionTree,
	poolTx string,
	aspPublicKey *secp256k1.PublicKey,
	roundLifetimeSeconds int64,
) error {
	poolTransaction, err := psetv2.NewPsetFromBase64(poolTx)
	if err != nil {
		return ErrInvalidPoolTransaction
	}

	if len(poolTransaction.Outputs) < sharedOutputIndex+1 {
		return ErrInvalidPoolTransactionOutputs
	}

	poolTxAmount := poolTransaction.Outputs[sharedOutputIndex].Value

	utx, err := poolTransaction.UnsignedTx()
	if err != nil {
		return ErrInvalidPoolTransaction
	}

	poolTxID := utx.TxHash().String()

	nbNodes := tree.NumberOfNodes()
	if nbNodes == 0 {
		return ErrEmptyTree
	}

	if len(tree[0]) != 1 {
		return ErrInvalidRootLevel
	}

	// check that root input is connected to the pool tx
	rootPsetB64 := tree[0][0].Tx
	rootPset, err := psetv2.NewPsetFromBase64(rootPsetB64)
	if err != nil {
		return fmt.Errorf("invalid root transaction: %w", err)
	}

	if len(rootPset.Inputs) != 1 {
		return ErrNumberOfInputs
	}

	rootInput := rootPset.Inputs[0]
	if chainhash.Hash(rootInput.PreviousTxid).String() != poolTxID || rootInput.PreviousTxIndex != sharedOutputIndex {
		return ErrWrongPoolTxID
	}

	sumRootValue := uint64(0)
	for _, output := range rootPset.Outputs {
		sumRootValue += output.Value
	}

	if sumRootValue != poolTxAmount {
		return ErrInvalidAmount
	}

	if len(tree.Leaves()) == 0 {
		return ErrNoLeaves
	}

	// iterates over all the nodes of the tree
	for _, level := range tree {
		for _, node := range level {
			if err := validateNodeTransaction(node, tree, UnspendableKey(), aspPublicKey, roundLifetimeSeconds); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateNodeTransaction(
	node Node,
	tree CongestionTree,
	expectedInternalKey,
	expectedPublicKeyASP *secp256k1.PublicKey,
	expectedSequenceSeconds int64,
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

	if chainhash.Hash(decodedPset.Inputs[0].PreviousTxid).String() != node.ParentTxid {
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

			if !bytes.Equal(schnorr.SerializePubKey(outputScript), previousScriptKey) {
				return ErrInvalidTaprootScript
			}

			close, err := DecodeClosure(tapLeaf.Script)
			if err != nil {
				continue
			}

			switch c := close.(type) {
			case *CSVSigClosure:
				isASP := bytes.Equal(schnorr.SerializePubKey(c.Pubkey), schnorr.SerializePubKey(expectedPublicKeyASP))
				isSweepDelay := int64(c.Seconds) == expectedSequenceSeconds

				if isASP && !isSweepDelay {
					return ErrInvalidSweepSequence
				}

				if isSweepDelay && !isASP {
					return ErrInvalidASP
				}

				if isASP && isSweepDelay {
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

				if !bytes.Equal(leftWitnessProgram, schnorr.SerializePubKey(c.LeftKey)) {
					return ErrInvalidLeftOutput
				}

				if c.LeftAmount != leftOutputAmount {
					return ErrInvalidLeftOutput
				}

				if c.RightKey != nil {
					rightWitnessProgram := childTx.Outputs[1].Script[2:]
					rightOutputAmount := childTx.Outputs[1].Value

					if !bytes.Equal(rightWitnessProgram, schnorr.SerializePubKey(c.RightKey)) {
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
