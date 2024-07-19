package utils

import (
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/taproot"
)

func ComputeVtxoTaprootScript(
	userPubkey, aspPubkey *secp256k1.PublicKey, exitDelay uint, net network.Network,
) (*secp256k1.PublicKey, *taproot.TapscriptElementsProof, []byte, string, error) {
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
		return nil, nil, nil, "", err
	}

	forfeitLeaf, err := forfeitClosure.Leaf()
	if err != nil {
		return nil, nil, nil, "", err
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

	pay, err := payment.FromTweakedKey(vtxoTaprootKey, &net, nil)
	if err != nil {
		return nil, nil, nil, "", err
	}

	addr, err := pay.TaprootAddress()
	if err != nil {
		return nil, nil, nil, "", err
	}

	script, err := address.ToOutputScript(addr)
	if err != nil {
		return nil, nil, nil, "", err
	}

	return vtxoTaprootKey, &proof, script, addr, nil
}

func NetworkFromString(net string) common.Network {
	switch net {
	case common.Liquid.Name:
		return common.Liquid
	case common.LiquidTestNet.Name:
		return common.LiquidTestNet
	case common.LiquidRegTest.Name:
		return common.LiquidRegTest
	case common.BitcoinTestNet.Name:
		return common.BitcoinTestNet
	case common.BitcoinRegTest.Name:
		return common.BitcoinRegTest
	case common.Bitcoin.Name:
		fallthrough
	default:
		return common.Bitcoin
	}
}
