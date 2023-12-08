package txbuilder

import (
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
)

const (
	sharedOutputIndex = 0
)

type outputScriptFactory func(leaves []domain.Receiver) ([]byte, error)

func p2wpkhScript(publicKey *secp256k1.PublicKey, net *network.Network) ([]byte, error) {
	payment := payment.FromPublicKey(publicKey, net, nil)
	addr, err := payment.WitnessPubKeyHash()
	if err != nil {
		return nil, err
	}

	return address.ToOutputScript(addr)
}

// newOtputScriptFactory returns an output script factory func that lock funds using the ASP public key only on all branches psbt. The leaves are instead locked by the leaf public key.
func newOutputScriptFactory(aspPublicKey *secp256k1.PublicKey, net *network.Network) outputScriptFactory {
	return func(leaves []domain.Receiver) ([]byte, error) {
		aspScript, err := p2wpkhScript(aspPublicKey, net)
		if err != nil {
			return nil, err
		}

		switch len(leaves) {
		case 0:
			return nil, nil
		case 1: // it's a leaf
			_, key, err := common.DecodePubKey(leaves[0].Pubkey)
			if err != nil {
				return nil, err
			}

			return p2wpkhScript(key, net)
		default: // it's a branch, lock funds with ASP public key
			return aspScript, nil
		}
	}
}

// congestionTree builder iteratively creates a binary tree of Pset from a set of receivers
// it also expect createOutputScript func managing the output script creation and the network to use (mainly for L-BTC asset id)
func buildCongestionTree(
	createOutputScript outputScriptFactory,
	net *network.Network,
	poolTxID string,
	receivers []domain.Receiver,
) (congestionTree domain.CongestionTree, err error) {
	var nodes []*node

	for _, r := range receivers {
		nodes = append(nodes, newLeaf(createOutputScript, net, r))
	}

	for len(nodes) > 1 {
		nodes, err = createTreeLevel(nodes)
		if err != nil {
			return nil, err
		}
	}

	psets, err := nodes[0].psets(psetv2.InputArgs{
		Txid:    poolTxID,
		TxIndex: sharedOutputIndex,
	}, 0)
	if err != nil {
		return nil, err
	}

	maxLevel := 0
	for _, psetWithLevel := range psets {
		if psetWithLevel.level > maxLevel {
			maxLevel = psetWithLevel.level
		}
	}

	tree := make(domain.CongestionTree, maxLevel+1)

	for _, psetWithLevel := range psets {
		utx, err := psetWithLevel.pset.UnsignedTx()
		if err != nil {
			return nil, err
		}

		txid := utx.TxHash().String()

		psetB64, err := psetWithLevel.pset.ToBase64()
		if err != nil {
			return nil, err
		}

		parentTxid := chainhash.Hash(psetWithLevel.pset.Inputs[0].PreviousTxid).String()

		tree[psetWithLevel.level] = append(tree[psetWithLevel.level], domain.Node{
			Txid:       txid,
			Tx:         psetB64,
			ParentTxid: parentTxid,
		})
	}

	return tree, nil
}

func createTreeLevel(nodes []*node) ([]*node, error) {
	if len(nodes)%2 != 0 {
		last := nodes[len(nodes)-1]
		pairs, err := createTreeLevel(nodes[:len(nodes)-1])
		if err != nil {
			return nil, err
		}

		return append(pairs, last), nil
	}

	pairs := make([]*node, 0, len(nodes)/2)
	for i := 0; i < len(nodes); i += 2 {
		pairs = append(pairs, newBranch(nodes[i], nodes[i+1]))
	}
	return pairs, nil
}

// internal struct to build a binary tree of Pset
type node struct {
	receivers          []domain.Receiver
	left               *node
	right              *node
	createOutputScript outputScriptFactory
	network            *network.Network
}

// create a node from a single receiver
func newLeaf(
	createOutputScript outputScriptFactory,
	network *network.Network,
	receiver domain.Receiver,
) *node {
	return &node{
		receivers:          []domain.Receiver{receiver},
		createOutputScript: createOutputScript,
		network:            network,
		left:               nil,
		right:              nil,
	}
}

// aggregate two nodes into a branch node
func newBranch(
	left *node,
	right *node,
) *node {
	return &node{
		receivers:          append(left.receivers, right.receivers...),
		createOutputScript: left.createOutputScript,
		network:            left.network,
		left:               left,
		right:              right,
	}
}

// is it the final node of the tree
func (n *node) isLeaf() bool {
	return len(n.receivers) == 1
}

// compute the output amount of a node
func (n *node) amount() uint64 {
	var amount uint64
	for _, r := range n.receivers {
		amount += r.Amount
	}
	return amount
}

// compute the output script of a node
func (n *node) script() ([]byte, error) {
	return n.createOutputScript(n.receivers)
}

// use script & amount to create OutputArgs
func (n *node) output() (*psetv2.OutputArgs, error) {
	script, err := n.script()
	if err != nil {
		return nil, err
	}

	return &psetv2.OutputArgs{
		Asset:  n.network.AssetID,
		Amount: n.amount(),
		Script: script,
	}, nil
}

// create the node Pset from the previous node Pset represented by input arg
// if node is a branch, it adds two outputs to the Pset, one for the left branch and one for the right branch
// if node is a leaf, it only adds one output to the Pset (the node output)
func (n *node) pset(input psetv2.InputArgs) (*psetv2.Pset, error) {
	pset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return nil, err
	}

	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return nil, err
	}

	err = updater.AddInputs([]psetv2.InputArgs{input})
	if err != nil {
		return nil, err
	}

	if n.isLeaf() {
		output, err := n.output()
		if err != nil {
			return nil, err
		}

		err = updater.AddOutputs([]psetv2.OutputArgs{*output})
		if err != nil {
			return nil, err
		}
		return pset, nil
	}

	outputLeft, err := n.left.output()
	if err != nil {
		return nil, err
	}

	outputRight, err := n.right.output()
	if err != nil {
		return nil, err
	}

	err = updater.AddOutputs([]psetv2.OutputArgs{*outputLeft, *outputRight})
	if err != nil {
		return nil, err
	}

	return pset, nil
}

type psetWithLevel struct {
	pset  *psetv2.Pset
	level int
}

// create the node pset and all the psets of its children recursively, updating the input arg at each step
// the function stops when it reaches a leaf node
func (n *node) psets(input psetv2.InputArgs, level int) ([]psetWithLevel, error) {
	pset, err := n.pset(input)
	if err != nil {
		return nil, err
	}

	nodeResult := []psetWithLevel{
		{pset, level},
	}

	if n.isLeaf() {
		return nodeResult, nil
	}

	unsignedTx, err := pset.UnsignedTx()
	if err != nil {
		return nil, err
	}

	txID := unsignedTx.TxHash().String()

	psetsLeft, err := n.left.psets(psetv2.InputArgs{
		Txid:    txID,
		TxIndex: 0,
	}, level+1)
	if err != nil {
		return nil, err
	}

	psetsRight, err := n.right.psets(psetv2.InputArgs{
		Txid:    txID,
		TxIndex: 1,
	}, level+1)
	if err != nil {
		return nil, err
	}

	return append(nodeResult, append(psetsLeft, psetsRight...)...), nil
}
