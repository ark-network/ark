package tree

import (
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/descriptor"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/taproot"
)

type VtxoScript common.VtxoScript[elementsTapTree]

func ParseVtxoScript(desc string) (VtxoScript, error) {
	v := &DefaultVtxoScript{}
	// TODO add other type
	err := v.FromDescriptor(desc)
	return v, err
}

/*
* DefaultVtxoScript is the default implementation of VTXO with 2 closures
* - Owner and ASP (forfeit)
*	- Owner after t (unilateral exit)
 */
type DefaultVtxoScript struct {
	Owner     *secp256k1.PublicKey
	Asp       *secp256k1.PublicKey
	ExitDelay uint
}

func (v *DefaultVtxoScript) ToDescriptor() string {
	owner := hex.EncodeToString(schnorr.SerializePubKey(v.Owner))

	return fmt.Sprintf(
		descriptor.DefaultVtxoDescriptorTemplate,
		hex.EncodeToString(UnspendableKey().SerializeCompressed()),
		owner,
		hex.EncodeToString(schnorr.SerializePubKey(v.Asp)),
		v.ExitDelay,
		owner,
	)
}

func (v *DefaultVtxoScript) FromDescriptor(desc string) error {
	owner, asp, exitDelay, err := descriptor.ParseDefaultVtxoDescriptor(desc)
	if err != nil {
		return err
	}

	v.Owner = owner
	v.Asp = asp
	v.ExitDelay = exitDelay
	return nil
}

func (v *DefaultVtxoScript) TapTree() (*secp256k1.PublicKey, elementsTapTree, error) {
	redeemClosure := &CSVSigClosure{
		Pubkey:  v.Owner,
		Seconds: v.ExitDelay,
	}

	redeemLeaf, err := redeemClosure.Leaf()
	if err != nil {
		return nil, elementsTapTree{}, err
	}

	forfeitClosure := &MultisigClosure{
		Pubkey:    v.Owner,
		AspPubkey: v.Asp,
	}

	forfeitLeaf, err := forfeitClosure.Leaf()
	if err != nil {
		return nil, elementsTapTree{}, err
	}

	tapTree := taproot.AssembleTaprootScriptTree(
		*redeemLeaf, *forfeitLeaf,
	)

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
