package bitcointree

import (
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type VtxoScript common.VtxoScript[bitcoinTapTree, tree.Closure]

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

func NewDefaultVtxoScript(owner, server *secp256k1.PublicKey, exitDelay common.RelativeLocktime) VtxoScript {
	base := tree.NewDefaultVtxoScript(owner, server, exitDelay)

	return &TapscriptsVtxoScript{*base}
}

type TapscriptsVtxoScript struct {
	tree.TapscriptsVtxoScript
}

func (v *TapscriptsVtxoScript) TapTree() (*secp256k1.PublicKey, bitcoinTapTree, error) {
	leaves := make([]txscript.TapLeaf, len(v.Closures))
	for i, closure := range v.Closures {
		script, err := closure.Script()
		if err != nil {
			return nil, bitcoinTapTree{}, fmt.Errorf("failed to get script for closure %d: %w", i, err)
		}
		leaves[i] = txscript.NewBaseTapLeaf(script)
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
