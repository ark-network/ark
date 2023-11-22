package application

import (
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
)

type outputScriptFactory func(leaves []ports.TreeLeaf) ([]byte, error)

type treeBuilder struct {
	createOutputScript outputScriptFactory
}

func (t *treeBuilder) BuildCongestionTree(poolTransaction string, leaves []ports.TreeLeaf) (ports.CongestionTree, error) {
	return nil, nil
}

// NewCentralizedTreeBuilder returns a TreeBuilder that creates a congestion tree where branches are locked by the ASP public key and leaves are locked by the leaf public key.
func NewCentralizedTreeBuilder(aspPublicKey *secp256k1.PublicKey, net *network.Network) ports.TreeBuilder {
	return &treeBuilder{
		createOutputScript: centralizedOutputScriptFactory(aspPublicKey, net),
	}
}

func p2wpkhScript(publicKey *secp256k1.PublicKey, net *network.Network) ([]byte, error) {
	payment := payment.FromPublicKey(publicKey, net, nil)
	addr, err := payment.WitnessPubKeyHash()
	if err != nil {
		return nil, err
	}

	return address.ToOutputScript(addr)
}

// centralizedOutputScriptFactory returns an output script factory func that lock funds using the ASP public key only on all branches psbt. The leaves are instead locked by the leaf public key.
func centralizedOutputScriptFactory(aspPublicKey *secp256k1.PublicKey, net *network.Network) outputScriptFactory {
	return func(leaves []ports.TreeLeaf) ([]byte, error) {
		aspScript, err := p2wpkhScript(aspPublicKey, net)
		if err != nil {
			return nil, err
		}

		switch len(leaves) {
		case 0:
			return nil, nil
		case 1: // it's a leaf
			_, pubkey, err := common.DecodePubKey(leaves[0].PublicKey())
			if err != nil {
				return nil, err
			}
			return p2wpkhScript(pubkey, net)
		default: // it's a branch, lock funds with ASP public key
			return aspScript, nil
		}
	}
}
