package tree

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/taproot"
)

type VtxoScript common.VtxoScript[elementsTapTree, *MultisigClosure, *CSVSigClosure]

func ParseVtxoScript(scripts []string) (VtxoScript, error) {
	v := &TapscriptsVtxoScript{}

	err := v.Decode(scripts)
	return v, err
}

func NewDefaultVtxoScript(owner, asp *secp256k1.PublicKey, exitDelay uint) *TapscriptsVtxoScript {
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
	encoded := make([]string, 0)
	for _, closure := range v.Closures {
		leaf, err := closure.Leaf()
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, hex.EncodeToString(leaf.Script))
	}
	return encoded, nil
}

func (v *TapscriptsVtxoScript) Decode(scripts []string) error {
	v.Closures = make([]Closure, 0, len(scripts))
	for _, script := range scripts {
		scriptBytes, err := hex.DecodeString(script)
		if err != nil {
			return err
		}

		closure, err := DecodeClosure(scriptBytes)
		if err != nil {
			return err
		}
		v.Closures = append(v.Closures, closure)
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

func (v *TapscriptsVtxoScript) TapTree() (*secp256k1.PublicKey, elementsTapTree, error) {
	leaves := make([]taproot.TapElementsLeaf, 0, len(v.Closures))
	for _, closure := range v.Closures {
		leaf, err := closure.Leaf()
		if err != nil {
			return nil, elementsTapTree{}, err
		}
		leaves = append(leaves, *leaf)
	}

	tapTree := taproot.AssembleTaprootScriptTree(leaves...)
	root := tapTree.RootNode.TapHash()
	taprootKey := taproot.ComputeTaprootOutputKey(UnspendableKey(), root[:])

	return taprootKey, elementsTapTree{tapTree}, nil
}

// elementsTapTree wraps the IndexedElementsTapScriptTree to implement the common.TaprootTree interface
type elementsTapTree struct {
	*taproot.IndexedElementsTapScriptTree
}

func (b elementsTapTree) GetRoot() chainhash.Hash {
	return b.RootNode.TapHash()
}

func (b elementsTapTree) GetTaprootMerkleProof(leafhash chainhash.Hash) (*common.TaprootMerkleProof, error) {
	index, ok := b.LeafProofIndex[leafhash]
	if !ok {
		return nil, fmt.Errorf("leaf %s not found in taproot tree", leafhash.String())
	}
	proof := b.LeafMerkleProofs[index]

	controlBlock := proof.ToControlBlock(UnspendableKey())
	controlBlockBytes, err := controlBlock.ToBytes()
	if err != nil {
		return nil, err
	}

	closure, err := DecodeClosure(proof.Script)
	if err != nil {
		return nil, err
	}

	return &common.TaprootMerkleProof{
		ControlBlock: controlBlockBytes,
		Script:       proof.Script,
		WitnessSize:  closure.WitnessSize(),
	}, nil
}

func (b elementsTapTree) GetLeaves() []chainhash.Hash {
	hashes := make([]chainhash.Hash, 0)
	for h := range b.LeafProofIndex {
		hashes = append(hashes, h)
	}
	return hashes
}
