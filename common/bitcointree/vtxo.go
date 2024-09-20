package bitcointree

import (
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/descriptor"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type VtxoScript common.VtxoScript[bitcoinTapTree]

func ParseVtxoScript(desc string) (VtxoScript, error) {
	v := &DefaultVtxoScript{}
	// TODO add other type
	err := v.FromDescriptor(desc)
	if err != nil {
		v := &ReversibleVtxoScript{}
		err = v.FromDescriptor(desc)
		if err != nil {
			return nil, fmt.Errorf("invalid vtxo descriptor: %s", desc)
		}

		return v, nil
	}

	return v, nil
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

func (v *DefaultVtxoScript) TapTree() (*secp256k1.PublicKey, bitcoinTapTree, error) {
	redeemClosure := &CSVSigClosure{
		Pubkey:  v.Owner,
		Seconds: v.ExitDelay,
	}

	redeemLeaf, err := redeemClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	forfeitClosure := &MultisigClosure{
		Pubkey:    v.Owner,
		AspPubkey: v.Asp,
	}

	forfeitLeaf, err := forfeitClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	tapTree := txscript.AssembleTaprootScriptTree(
		*redeemLeaf, *forfeitLeaf,
	)

	root := tapTree.RootNode.TapHash()
	taprootKey := txscript.ComputeTaprootOutputKey(
		UnspendableKey(),
		root[:],
	)

	return taprootKey, bitcoinTapTree{tapTree}, nil
}

/*
* ReversibleVtxoScript allows sender of the VTXO to revert the transaction
* unilateral exit is in favor of the sender
* - Owner and ASP (forfeit owner)
* - Sender and ASP (forfeit sender)
*	- Sender after t (unilateral exit)
 */
type ReversibleVtxoScript struct {
	Asp       *secp256k1.PublicKey
	Sender    *secp256k1.PublicKey
	Owner     *secp256k1.PublicKey
	ExitDelay uint
}

func (v *ReversibleVtxoScript) ToDescriptor() string {
	owner := hex.EncodeToString(schnorr.SerializePubKey(v.Owner))
	sender := hex.EncodeToString(schnorr.SerializePubKey(v.Sender))
	asp := hex.EncodeToString(schnorr.SerializePubKey(v.Asp))

	return fmt.Sprintf(
		descriptor.ReversibleVtxoScriptTemplate,
		hex.EncodeToString(UnspendableKey().SerializeCompressed()),
		sender,
		asp,
		v.ExitDelay,
		sender,
		owner,
		asp,
	)
}

func (v *ReversibleVtxoScript) FromDescriptor(desc string) error {
	owner, sender, asp, exitDelay, err := descriptor.ParseReversibleVtxoDescriptor(desc)
	if err != nil {
		return err
	}

	v.Owner = owner
	v.Sender = sender
	v.Asp = asp
	v.ExitDelay = exitDelay
	return nil
}

func (v *ReversibleVtxoScript) TapTree() (*secp256k1.PublicKey, bitcoinTapTree, error) {
	redeemClosure := &CSVSigClosure{
		Pubkey:  v.Sender,
		Seconds: v.ExitDelay,
	}

	redeemLeaf, err := redeemClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	forfeitClosure := &MultisigClosure{
		Pubkey:    v.Owner,
		AspPubkey: v.Asp,
	}

	forfeitLeaf, err := forfeitClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	reverseForfeitClosure := &MultisigClosure{
		Pubkey:    v.Sender,
		AspPubkey: v.Asp,
	}

	reverseForfeitLeaf, err := reverseForfeitClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	tapTree := txscript.AssembleTaprootScriptTree(
		*redeemLeaf, *forfeitLeaf, *reverseForfeitLeaf,
	)

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
