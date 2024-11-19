package bitcointree

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type VtxoScript common.VtxoScript[bitcoinTapTree, *MultisigClosure, *CSVSigClosure]

func ParseVtxoScript(scripts []string) (VtxoScript, error) {
	types := []VtxoScript{
		&TapscriptsVtxoScript{},
	}

	for _, v := range types {
		if err := v.Decode(scripts); err == nil {
			return v, nil
		}
	}

	return nil, fmt.Errorf("invalid vtxo scripts: %s", scripts)
}

func NewDefaultVtxoScript(owner, asp *secp256k1.PublicKey, exitDelay uint) VtxoScript {
	return &TapscriptsVtxoScript{
		[]Closure{
			&CSVSigClosure{Pubkey: owner, Seconds: exitDelay},
			&MultisigClosure{Pubkey: owner, AspPubkey: asp},
		},
	}
}

type TapscriptsVtxoScript struct {
	Closures []Closure
}

func (v *TapscriptsVtxoScript) Encode() ([]string, error) {
	scripts := make([]string, len(v.Closures))
	for i, closure := range v.Closures {
		leaf, err := closure.Leaf()
		if err != nil {
			return nil, fmt.Errorf("failed to get leaf for closure %d: %w", i, err)
		}
		scripts[i] = hex.EncodeToString(leaf.Script)
	}

	return scripts, nil
}

func (v *TapscriptsVtxoScript) Decode(scripts []string) error {
	v.Closures = make([]Closure, len(scripts))
	for i, scriptHex := range scripts {
		script, err := hex.DecodeString(scriptHex)
		if err != nil {
			return fmt.Errorf("invalid script hex: %w", err)
		}

		// Parse script into appropriate closure type
		closure, err := DecodeClosure(script)
		if err != nil {
			return fmt.Errorf("failed to parse closure: %w", err)
		}
		v.Closures[i] = closure
	}

	return nil
}

func (v *TapscriptsVtxoScript) Validate(asp *secp256k1.PublicKey) error {
	for _, closure := range v.Closures {
		if multisigClosure, ok := closure.(*MultisigClosure); ok {
			if !bytes.Equal(schnorr.SerializePubKey(multisigClosure.AspPubkey), schnorr.SerializePubKey(asp)) {
				return fmt.Errorf("invalid forfeit closure, ASP pubkey not found")
			}
		}
	}

	return nil
}

func (v *TapscriptsVtxoScript) SmallestExitDelay() (uint, error) {
	smallest := uint(math.MaxUint32)

	for _, closure := range v.Closures {
		if csvClosure, ok := closure.(*CSVSigClosure); ok {
			if csvClosure.Seconds < smallest {
				smallest = csvClosure.Seconds
			}
		}
	}

	if smallest == math.MaxUint32 {
		return 0, fmt.Errorf("no exit delay found")
	}

	return smallest, nil
}

func (v *TapscriptsVtxoScript) ForfeitClosures() []*MultisigClosure {
	forfeits := make([]*MultisigClosure, 0)
	for _, closure := range v.Closures {
		if multisigClosure, ok := closure.(*MultisigClosure); ok {
			forfeits = append(forfeits, multisigClosure)
		}
	}
	return forfeits
}

func (v *TapscriptsVtxoScript) ExitClosures() []*CSVSigClosure {
	exits := make([]*CSVSigClosure, 0)
	for _, closure := range v.Closures {
		if csvClosure, ok := closure.(*CSVSigClosure); ok {
			exits = append(exits, csvClosure)
		}
	}
	return exits
}

func (v *TapscriptsVtxoScript) TapTree() (*secp256k1.PublicKey, bitcoinTapTree, error) {
	leaves := make([]txscript.TapLeaf, len(v.Closures))
	for i, closure := range v.Closures {
		leaf, err := closure.Leaf()
		if err != nil {
			return nil, bitcoinTapTree{}, fmt.Errorf("failed to get leaf for closure %d: %w", i, err)
		}
		leaves[i] = *leaf
	}

	tapTree := txscript.AssembleTaprootScriptTree(leaves...)
	root := tapTree.RootNode.TapHash()
	taprootKey := txscript.ComputeTaprootOutputKey(
		UnspendableKey(),
		root[:],
	)

	return taprootKey, bitcoinTapTree{tapTree}, nil
}

// bitcoinTapTree is a wrapper around txscript.IndexedTapScriptTree to implement the common.TaprootTree interface
type bitcoinTapTree struct {
	*txscript.IndexedTapScriptTree
}

func (b bitcoinTapTree) GetRoot() chainhash.Hash {
	return b.RootNode.TapHash()
}

func (b bitcoinTapTree) GetTaprootMerkleProof(leafhash chainhash.Hash) (*common.TaprootMerkleProof, error) {
	index, ok := b.LeafProofIndex[leafhash]
	if !ok {
		return nil, fmt.Errorf("leaf %s not found in tree", leafhash.String())
	}
	proof := b.LeafMerkleProofs[index]

	controlBlock := proof.ToControlBlock(UnspendableKey())
	controlBlockBytes, err := controlBlock.ToBytes()
	if err != nil {
		return nil, err
	}

	return &common.TaprootMerkleProof{
		ControlBlock: controlBlockBytes,
		Script:       proof.Script,
	}, nil
}

func (b bitcoinTapTree) GetLeaves() []chainhash.Hash {
	leafHashes := make([]chainhash.Hash, 0)
	for hash := range b.LeafProofIndex {
		leafHashes = append(leafHashes, hash)
	}
	return leafHashes
}
