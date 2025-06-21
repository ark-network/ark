package tree

import (
	"bytes"
	"fmt"

	"github.com/ark-network/ark/common"
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
	ErrNoLeaves                   = fmt.Errorf("no leaves in the tree")
	ErrInvalidTaprootScript       = fmt.Errorf("invalid taproot script")
	ErrMissingCosignersPublicKeys = fmt.Errorf("missing cosigners public keys")
	ErrInvalidAmount              = fmt.Errorf("children amount is different from parent amount")
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

// ValidateVtxoTxGraph checks if the given vtxo tree is valid
// roundTxid & roundTxIndex & roundTxAmount are used to validate the root input outpoint
// serverPubkey & vtxoTreeExpiry are used to validate the sweep tapscript leaves
// besides that, the function validates:
// - the number of nodes
// - the number of leaves
// - children coherence with parent
// - every control block and taproot output scripts
// - input and output amounts
func ValidateVtxoTxGraph(
	graph *TxGraph, roundTransaction *psbt.Packet, serverPubkey *secp256k1.PublicKey, vtxoTreeExpiry common.RelativeLocktime,
) error {
	if len(roundTransaction.Outputs) < sharedOutputIndex+1 {
		return ErrInvalidRoundTxOutputs
	}

	roundTxAmount := roundTransaction.UnsignedTx.TxOut[sharedOutputIndex].Value

	if graph.Root == nil {
		return ErrEmptyTree
	}

	rootInput := graph.Root.UnsignedTx.TxIn[0]
	if chainhash.Hash(rootInput.PreviousOutPoint.Hash).String() != roundTransaction.UnsignedTx.TxID() ||
		rootInput.PreviousOutPoint.Index != sharedOutputIndex {
		return ErrWrongRoundTxid
	}

	sumRootValue := int64(0)
	for _, output := range graph.Root.UnsignedTx.TxOut {
		sumRootValue += output.Value
	}

	if sumRootValue != roundTxAmount {
		return ErrInvalidAmount
	}

	if len(graph.Leaves()) == 0 {
		return ErrNoLeaves
	}

	sweepClosure := &CSVMultisigClosure{
		MultisigClosure: MultisigClosure{PubKeys: []*secp256k1.PublicKey{serverPubkey}},
		Locktime:        vtxoTreeExpiry,
	}

	sweepScript, err := sweepClosure.Script()
	if err != nil {
		return err
	}

	sweepLeaf := txscript.NewBaseTapLeaf(sweepScript)
	tapTree := txscript.AssembleTaprootScriptTree(sweepLeaf)
	tapTreeRoot := tapTree.RootNode.TapHash()

	// validate the graph structure
	if err := graph.Validate(); err != nil {
		return err
	}

	// iterates over all the nodes of the graph to verify that cosigners public keys are corresponding to the parent output
	if err := graph.Apply(func(g *TxGraph) (bool, error) {
		for childIndex, child := range g.Children {
			parentOutput := g.Root.UnsignedTx.TxOut[childIndex]
			previousScriptKey := parentOutput.PkScript[2:]
			if len(previousScriptKey) != 32 {
				return false, ErrInvalidTaprootScript
			}

			cosigners, err := GetCosignerKeys(child.Root.Inputs[0])
			if err != nil {
				return false, fmt.Errorf("unable to get cosigners keys: %w", err)
			}

			cosigners = uniqueCosigners(cosigners)

			if len(cosigners) == 0 {
				return false, ErrMissingCosignersPublicKeys
			}

			aggregatedKey, err := AggregateKeys(cosigners, tapTreeRoot.CloneBytes())
			if err != nil {
				return false, fmt.Errorf("unable to aggregate keys: %w", err)
			}

			if !bytes.Equal(schnorr.SerializePubKey(aggregatedKey.FinalKey), previousScriptKey) {
				return false, ErrInvalidTaprootScript
			}
		}
		return true, nil
	}); err != nil {
		return err
	}

	return nil
}
