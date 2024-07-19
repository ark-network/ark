package arksdk

import (
	"fmt"
	"sort"

	"github.com/ark-network/ark-sdk/client"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/address"
)

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

func coinSelect(vtxos []*client.Vtxo, amount uint64, sortByExpirationTime bool) ([]*client.Vtxo, uint64, error) {
	selected := make([]*client.Vtxo, 0)
	notSelected := make([]*client.Vtxo, 0)
	selectedAmount := uint64(0)

	if sortByExpirationTime {
		// sort vtxos by expiration (older first)
		sort.SliceStable(vtxos, func(i, j int) bool {
			if vtxos[i].ExpiresAt == nil || vtxos[j].ExpiresAt == nil {
				return false
			}

			return vtxos[i].ExpiresAt.Before(*vtxos[j].ExpiresAt)
		})
	}

	for _, vtxo := range vtxos {
		if selectedAmount >= amount {
			notSelected = append(notSelected, vtxo)
			break
		}

		selected = append(selected, vtxo)
		selectedAmount += vtxo.Amount
	}

	if selectedAmount < amount {
		return nil, 0, fmt.Errorf("not enough funds to cover amount%d", amount)
	}

	change := selectedAmount - amount

	if change < DUST {
		if len(notSelected) > 0 {
			selected = append(selected, notSelected[0])
			change += notSelected[0].Amount
		}
	}

	return selected, change, nil
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
