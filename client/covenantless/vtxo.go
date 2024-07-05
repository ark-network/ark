package covenantless

import (
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/taproot"
)

func computeVtxoTaprootScript(
	userPubkey, aspPubkey *secp256k1.PublicKey, exitDelay uint,
) (*secp256k1.PublicKey, *txscript.TapscriptProof, error) {
	redeemClosure := &bitcointree.CSVSigClosure{
		Pubkey:  userPubkey,
		Seconds: exitDelay,
	}

	forfeitClosure := &bitcointree.ForfeitClosure{
		Pubkey:    userPubkey,
		AspPubkey: aspPubkey,
	}

	redeemLeaf, err := redeemClosure.Leaf()
	if err != nil {
		return nil, nil, err
	}

	forfeitLeaf, err := forfeitClosure.Leaf()
	if err != nil {
		return nil, nil, err
	}

	vtxoTaprootTree := txscript.AssembleTaprootScriptTree(
		*redeemLeaf, *forfeitLeaf,
	)
	root := vtxoTaprootTree.RootNode.TapHash()

	unspendableKey := bitcointree.UnspendableKey()
	vtxoTaprootKey := taproot.ComputeTaprootOutputKey(unspendableKey, root[:])

	redeemLeafHash := redeemLeaf.TapHash()
	proofIndex := vtxoTaprootTree.LeafProofIndex[redeemLeafHash]
	proof := vtxoTaprootTree.LeafMerkleProofs[proofIndex]

	return vtxoTaprootKey, &proof, nil
}
