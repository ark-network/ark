package liquidwallet

import (
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/taproot"
)

func toElementsNetwork(net common.Network) network.Network {
	switch net.Name {
	case common.Liquid.Name:
		return network.Liquid
	case common.LiquidTestNet.Name:
		return network.Testnet
	case common.LiquidRegTest.Name:
		return network.Regtest
	default:
		return network.Liquid
	}
}

func computeVtxoTaprootScript(
	userPubkey, aspPubkey *secp256k1.PublicKey, exitDelay uint,
) (*secp256k1.PublicKey, *taproot.TapscriptElementsProof, error) {
	redeemClosure := &tree.CSVSigClosure{
		Pubkey:  userPubkey,
		Seconds: exitDelay,
	}

	forfeitClosure := &tree.ForfeitClosure{
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

	vtxoTaprootTree := taproot.AssembleTaprootScriptTree(
		*redeemLeaf, *forfeitLeaf,
	)
	root := vtxoTaprootTree.RootNode.TapHash()

	unspendableKey := tree.UnspendableKey()
	vtxoTaprootKey := taproot.ComputeTaprootOutputKey(unspendableKey, root[:])

	redeemLeafHash := redeemLeaf.TapHash()
	proofIndex := vtxoTaprootTree.LeafProofIndex[redeemLeafHash]
	proof := vtxoTaprootTree.LeafMerkleProofs[proofIndex]

	return vtxoTaprootKey, &proof, nil
}
