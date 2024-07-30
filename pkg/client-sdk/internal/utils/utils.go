package utils

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ark-network/ark-sdk/client"
	"github.com/ark-network/ark-sdk/explorer"
	liquidexplorer "github.com/ark-network/ark-sdk/explorer/liquid"
	"github.com/ark-network/ark-sdk/store"
	"github.com/ark-network/ark-sdk/wallet"
	liquidwallet "github.com/ark-network/ark-sdk/wallet/singlekey/liquid"
	walletstore "github.com/ark-network/ark-sdk/wallet/singlekey/store"
	filestore "github.com/ark-network/ark-sdk/wallet/singlekey/store/file"
	inmemorystore "github.com/ark-network/ark-sdk/wallet/singlekey/store/inmemory"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/address"
)

func ToCongestionTree(treeFromProto *arkv1.Tree) (tree.CongestionTree, error) {
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

func CastCongestionTree(congestionTree tree.CongestionTree) *arkv1.Tree {
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

func CoinSelect(
	vtxos []*client.Vtxo, amount, dust uint64, sortByExpirationTime bool,
) ([]*client.Vtxo, uint64, error) {
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

	if change < dust {
		if len(notSelected) > 0 {
			selected = append(selected, notSelected[0])
			change += notSelected[0].Amount
		}
	}

	return selected, change, nil
}

func DecodeReceiverAddress(addr string) (
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

func IsOnchainOnly(receivers []*arkv1.Output) bool {
	for _, receiver := range receivers {
		isOnChain, _, _, err := DecodeReceiverAddress(receiver.Address)
		if err != nil {
			continue
		}

		if !isOnChain {
			return false
		}
	}

	return true
}

func GetClient(
	supportedClients SupportedType[ClientFactory], clientType, aspUrl string,
) (client.ASPClient, error) {
	factory := supportedClients[clientType]
	return factory(aspUrl)
}

func GetExplorer(
	supportedNetworks SupportedType[string], network string,
) (explorer.Explorer, error) {
	url, ok := supportedNetworks[network]
	if !ok {
		return nil, fmt.Errorf("invalid network")
	}
	if strings.Contains(network, "liquid") {
		return liquidexplorer.NewExplorer(url, network), nil
	}
	// TODO: support bitcoin explorer
	return nil, fmt.Errorf("network not supported yet")
}

func GetWallet(
	storeSvc store.ConfigStore, data *store.StoreData, supportedWallets SupportedType[struct{}],
) (wallet.WalletService, error) {
	switch data.WalletType {
	case wallet.SingleKeyWallet:
		return getSingleKeyWallet(storeSvc, data.Network.Name)
	default:
		return nil, fmt.Errorf(
			"unsuported wallet type '%s', please select one of: %s",
			data.WalletType, supportedWallets,
		)
	}
}

func getSingleKeyWallet(
	configStore store.ConfigStore, network string,
) (wallet.WalletService, error) {
	walletStore, err := getWalletStore(configStore.GetType(), configStore.GetDatadir())
	if err != nil {
		return nil, err
	}
	if strings.Contains(network, "liquid") {
		return liquidwallet.NewWalletService(configStore, walletStore)
	}
	// TODO: Support bitcoin wallet
	return nil, fmt.Errorf("network %s not supported yet", network)
}

func getWalletStore(storeType, datadir string) (walletstore.WalletStore, error) {
	switch storeType {
	case store.InMemoryStore:
		return inmemorystore.NewWalletStore()
	case store.FileStore:
		return filestore.NewWalletStore(datadir)
	default:
		return nil, fmt.Errorf("unknown wallet store type")
	}
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
