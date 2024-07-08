package arksdk

import (
	"fmt"
	"io"
	"net/http"
	"sort"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
)

func getAddress(
	walletPubKey []byte,
	aspPubKey []byte,
	unilateralExitDelay int64,
	net string,
) (offchainAddr, onchainAddr, redemptionAddr string, err error) {
	userPubkey, err := secp256k1.ParsePubKey(walletPubKey)
	if err != nil {
		return
	}

	aspPubkey, err := secp256k1.ParsePubKey(aspPubKey)
	if err != nil {
		return
	}

	arkNet, liquidNet := networkFromString(net)

	arkAddr, err := common.EncodeAddress(arkNet.Addr, userPubkey, aspPubkey)
	if err != nil {
		return
	}

	p2wpkh := payment.FromPublicKey(userPubkey, liquidNet, nil)
	liquidAddr, err := p2wpkh.WitnessPubKeyHash()
	if err != nil {
		return
	}

	vtxoTapKey, _, err := computeVtxoTaprootScript(
		userPubkey, aspPubkey, uint(unilateralExitDelay),
	)
	if err != nil {
		return
	}

	_, n := networkFromString(net)

	pay, err := payment.FromTweakedKey(vtxoTapKey, n, nil)
	if err != nil {
		return
	}

	redemptionAddr, err = pay.TaprootAddress()
	if err != nil {
		return
	}

	offchainAddr = arkAddr
	onchainAddr = liquidAddr

	return
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

func toCongestionTree(treeFromProto *arkv1.Tree) (tree.CongestionTree, error) {
	levels := make(tree.CongestionTree, 0, len(treeFromProto.Levels))

	for _, level := range treeFromProto.Levels {
		nodes := make([]tree.Node, 0, len(level.Nodes))

		for _, node := range level.Nodes {
			nodes = append(nodes, tree.Node{
				Txid:       node.Txid,
				Tx:         node.Tx,
				ParentTxid: node.ParentTxid,
				Leaf:       false,
			})
		}

		levels = append(levels, nodes)
	}

	for j, treeLvl := range levels {
		for i, node := range treeLvl {
			if len(levels.Children(node.Txid)) == 0 {
				levels[j][i].Leaf = true
			}
		}
	}

	return levels, nil
}

func networkFromString(net string) (*common.Network, *network.Network) {
	if net == "testnet" {
		return &common.TestNet, &network.Testnet
	}
	if net == "regtest" {
		return &common.RegTest, &network.Regtest
	}
	return &common.Liquid, &network.Liquid
}

func testEsploraEndpoint(net *network.Network, url string) error {
	resp, err := http.Get(fmt.Sprintf("%s/asset/%s", url, net.AssetID))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(string(body))
	}

	return nil
}

func castCongestionTree(congestionTree tree.CongestionTree) *arkv1.Tree {
	levels := make([]*arkv1.TreeLevel, 0, len(congestionTree))
	for _, level := range congestionTree {
		levelProto := &arkv1.TreeLevel{
			Nodes: make([]*arkv1.Node, 0, len(level)),
		}

		for _, node := range level {
			levelProto.Nodes = append(levelProto.Nodes, &arkv1.Node{
				Txid:       node.Txid,
				Tx:         node.Tx,
				ParentTxid: node.ParentTxid,
			})
		}

		levels = append(levels, levelProto)
	}
	return &arkv1.Tree{
		Levels: levels,
	}
}

func coinSelect(vtxos []vtxo, amount uint64, sortByExpirationTime bool) ([]vtxo, uint64, error) {
	selected := make([]vtxo, 0)
	notSelected := make([]vtxo, 0)
	selectedAmount := uint64(0)

	if sortByExpirationTime {
		// sort vtxos by expiration (older first)
		sort.SliceStable(vtxos, func(i, j int) bool {
			if vtxos[i].expireAt == nil || vtxos[j].expireAt == nil {
				return false
			}

			return vtxos[i].expireAt.Before(*vtxos[j].expireAt)
		})
	}

	for _, vtxo := range vtxos {
		if selectedAmount >= amount {
			notSelected = append(notSelected, vtxo)
			break
		}

		selected = append(selected, vtxo)
		selectedAmount += vtxo.amount
	}

	if selectedAmount < amount {
		return nil, 0, fmt.Errorf("not enough funds to cover amount%d", amount)
	}

	change := selectedAmount - amount

	if change < DUST {
		if len(notSelected) > 0 {
			selected = append(selected, notSelected[0])
			change += notSelected[0].amount
		}
	}

	return selected, change, nil
}

func findSweepClosure(
	congestionTree tree.CongestionTree,
) (*taproot.TapElementsLeaf, uint, error) {
	root, err := congestionTree.Root()
	if err != nil {
		return nil, 0, err
	}

	// find the sweep closure
	tx, err := psetv2.NewPsetFromBase64(root.Tx)
	if err != nil {
		return nil, 0, err
	}

	var seconds uint
	var sweepClosure *taproot.TapElementsLeaf
	for _, tapLeaf := range tx.Inputs[0].TapLeafScript {
		closure := &tree.CSVSigClosure{}
		valid, err := closure.Decode(tapLeaf.Script)
		if err != nil {
			continue
		}

		if valid && closure.Seconds > seconds {
			seconds = closure.Seconds
			sweepClosure = &tapLeaf.TapElementsLeaf
		}
	}

	if sweepClosure == nil {
		return nil, 0, fmt.Errorf("sweep closure not found")
	}

	return sweepClosure, seconds, nil
}

func decodeReceiverAddress(addr string) (
	bool, []byte, *secp256k1.PublicKey, error,
) {
	outputScript, err := address.ToOutputScript(addr)
	if err != nil {
		_, userPubkey, _, err := common.DecodeAddress(addr)
		if err != nil {
			return false, nil, nil, err
		}
		return false, nil, userPubkey, nil
	}

	return true, outputScript, nil, nil
}

func isOnchainOnly(receivers []*arkv1.Output) bool {
	for _, receiver := range receivers {
		isOnChain, _, _, err := decodeReceiverAddress(receiver.Address)
		if err != nil {
			continue
		}

		if !isOnChain {
			return false
		}
	}

	return true
}
