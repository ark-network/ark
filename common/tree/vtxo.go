package tree

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/taproot"
)

var (
	ErrNoExitLeaf = fmt.Errorf("no exit leaf")
)

type VtxoScript common.VtxoScript[elementsTapTree, Closure]

func ParseVtxoScript(scripts []string) (VtxoScript, error) {
	v := &TapscriptsVtxoScript{}

	err := v.Decode(scripts)
	return v, err
}

func NewDefaultVtxoScript(owner, server *secp256k1.PublicKey, exitDelay common.RelativeLocktime) *TapscriptsVtxoScript {
	return &TapscriptsVtxoScript{
		[]Closure{
			&CSVMultisigClosure{
				MultisigClosure: MultisigClosure{PubKeys: []*secp256k1.PublicKey{owner}},
				Locktime:        exitDelay,
			},
			&MultisigClosure{PubKeys: []*secp256k1.PublicKey{owner, server}},
		},
	}
}

// TapscriptsVtxoScript represents a taproot script that contains a list of tapscript leaves
// the key-path is always unspendable
type TapscriptsVtxoScript struct {
	Closures []Closure
}

func (v *TapscriptsVtxoScript) Encode() ([]string, error) {
	encoded := make([]string, 0)
	for _, closure := range v.Closures {
		script, err := closure.Script()
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, hex.EncodeToString(script))
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

func (v *TapscriptsVtxoScript) Validate(server *secp256k1.PublicKey, minLocktime common.RelativeLocktime) error {
	serverXonly := schnorr.SerializePubKey(server)
	for _, forfeit := range v.ForfeitClosures() {
		multisigClosure, ok := forfeit.(*MultisigClosure)
		if !ok {
			return fmt.Errorf("invalid forfeit closure, expected MultisigClosure")
		}

		// must contain server pubkey
		found := false
		for _, pubkey := range multisigClosure.PubKeys {
			if bytes.Equal(schnorr.SerializePubKey(pubkey), serverXonly) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid forfeit closure, server pubkey not found")
		}
	}

	smallestExit, err := v.SmallestExitDelay()
	if err != nil {
		if err == ErrNoExitLeaf {
			return nil
		}
		return err
	}

	if smallestExit.LessThan(minLocktime) {
		return fmt.Errorf("exit delay is too short")
	}

	return nil
}

func (v *TapscriptsVtxoScript) SmallestExitDelay() (*common.RelativeLocktime, error) {
	var smallest *common.RelativeLocktime

	for _, closure := range v.Closures {
		if csvClosure, ok := closure.(*CSVMultisigClosure); ok {
			if smallest == nil || csvClosure.Locktime.LessThan(*smallest) {
				smallest = &csvClosure.Locktime
			}
		}
	}

	if smallest == nil {
		return nil, ErrNoExitLeaf
	}

	return smallest, nil
}

func (v *TapscriptsVtxoScript) ForfeitClosures() []Closure {
	forfeits := make([]Closure, 0)
	for _, closure := range v.Closures {
		switch closure.(type) {
		case *MultisigClosure, *CLTVMultisigClosure, *ConditionMultisigClosure:
			forfeits = append(forfeits, closure)
		}
	}
	return forfeits
}

func (v *TapscriptsVtxoScript) ExitClosures() []Closure {
	exits := make([]Closure, 0)
	for _, closure := range v.Closures {
		switch closure.(type) {
		case *CSVMultisigClosure:
			exits = append(exits, closure)
		}
	}
	return exits
}

func (v *TapscriptsVtxoScript) TapTree() (*secp256k1.PublicKey, elementsTapTree, error) {
	leaves := make([]taproot.TapElementsLeaf, 0, len(v.Closures))
	for _, closure := range v.Closures {
		leaf, err := closure.Script()
		if err != nil {
			return nil, elementsTapTree{}, err
		}
		leaves = append(leaves, taproot.NewBaseTapElementsLeaf(leaf))
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

	return &common.TaprootMerkleProof{
		ControlBlock: controlBlockBytes,
		Script:       proof.Script,
	}, nil
}

func (b elementsTapTree) GetLeaves() []chainhash.Hash {
	hashes := make([]chainhash.Hash, 0)
	for h := range b.LeafProofIndex {
		hashes = append(hashes, h)
	}
	return hashes
}
