package arksdk

import (
	"fmt"

	"github.com/ark-network/ark-sdk/client"
	grpcclient "github.com/ark-network/ark-sdk/client/grpc"
	restclient "github.com/ark-network/ark-sdk/client/rest"
	"github.com/ark-network/ark-sdk/explorer"
	liquidexplorer "github.com/ark-network/ark-sdk/explorer/liquid"
	"github.com/ark-network/ark-sdk/wallet"
	"github.com/ark-network/ark/common"
)

var (
	supportedWallets = supportedType[wallet.WalletFactory]{
		"singlekey": wallet.NewSingleKeyWallet,
	}
	supportedClients = supportedType[client.ClientFactory]{
		"grpc": grpcclient.NewClient,
		"rest": restclient.NewClient,
	}
	supportedNetworks = supportedType[string]{
		common.Liquid.Name:         "https://blockstream.info/liquid/api",
		common.LiquidTestNet.Name:  "https://blockstream.info/liquidtestnet/api",
		common.LiquidRegTest.Name:  "http://localhost:3001",
		common.Bitcoin.Name:        "https://blockstream.info/api",
		common.BitcoinTestNet.Name: "https://blockstream.info/testnet/api",
		common.BitcoinRegTest.Name: "http://localhost:3000",
	}
)

type InitArgs struct {
	WalletType  string
	ClientType  string
	Network     string
	AspUrl      string
	ExplorerUrl string
	Password    string
	PrivateKey  string
}

func (a InitArgs) validate() error {
	if len(a.WalletType) <= 0 {
		return fmt.Errorf("missing wallet type")
	}
	if !supportedWallets.supports(a.WalletType) {
		return fmt.Errorf("wallet type not supported, please select one of: %s", supportedWallets)
	}

	if len(a.ClientType) <= 0 {
		return fmt.Errorf("missing client type")
	}
	if !supportedClients.supports(a.ClientType) {
		return fmt.Errorf("client type not supported, please select one of: %s", supportedClients)
	}

	if len(a.Network) <= 0 {
		return fmt.Errorf("missing network")
	}
	if !supportedNetworks.supports(a.Network) {
		return fmt.Errorf("network not supported, please select one of: %s", supportedNetworks)
	}
	if len(a.AspUrl) <= 0 {
		return fmt.Errorf("missing asp url")
	}
	if len(a.Password) <= 0 {
		return fmt.Errorf("missing password")
	}
	return nil
}

func (a InitArgs) wallet(
	args ...interface{},
) (wallet.Wallet, error) {
	factory := supportedWallets[a.WalletType]
	return factory(args...)
}

func (a InitArgs) client(args ...interface{}) (client.Client, error) {
	factory := supportedClients[a.ClientType]
	args = append([]interface{}{a.AspUrl}, args...)
	return factory(args...)
}

func (a InitArgs) explorer() (explorer.Explorer, error) {
	url := supportedNetworks[a.Network]
	if len(a.ExplorerUrl) > 0 {
		url = a.ExplorerUrl
	}
	return liquidexplorer.NewExplorer(url, a.Network), nil
}

type Balance struct {
	OnchainBalance  OnchainBalance  `json:"onchain_balance"`
	OffchainBalance OffchainBalance `json:"offchain_balance"`
}

type OnchainBalance struct {
	SpendableAmount uint64                 `json:"spendable_amount"`
	LockedAmount    []LockedOnchainBalance `json:"locked_amount,omitempty"`
}

type LockedOnchainBalance struct {
	SpendableAt string `json:"spendable_at"`
	Amount      uint64 `json:"amount"`
}

type OffchainBalance struct {
	Total          uint64        `json:"total"`
	NextExpiration string        `json:"next_expiration,omitempty"`
	Details        []VtxoDetails `json:"details"`
}

type VtxoDetails struct {
	ExpiryTime string `json:"expiry_time"`
	Amount     uint64 `json:"amount"`
}

type balanceRes struct {
	offchainBalance             uint64
	onchainSpendableBalance     uint64
	onchainLockedBalance        map[int64]uint64
	offchainBalanceByExpiration map[int64]uint64
	err                         error
}
