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
		return nil, fmt.Errorf("unknown vtxo script type: %s (%s)", desc, err)
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
	taprootDesc, err := descriptor.ParseTaprootDescriptor(desc)
	if err != nil {
		return err
	}

	owner, asp, exitDelay, err := descriptor.ParseDefaultVtxoDescriptor(*taprootDesc)
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
		return nil, common.ErrLeafNotFound
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
