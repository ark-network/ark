package arksdk

import (
	"fmt"
	"strings"

	"github.com/ark-network/ark-sdk/client"
	grpcclient "github.com/ark-network/ark-sdk/client/grpc"
	restclient "github.com/ark-network/ark-sdk/client/rest"
	"github.com/ark-network/ark-sdk/explorer"
	liquidexplorer "github.com/ark-network/ark-sdk/explorer/liquid"
	"github.com/ark-network/ark-sdk/wallet"
	"github.com/ark-network/ark/common"
)

var (
	supportedWallets = supportedType[struct{}]{
		wallet.SingleKeyWallet: struct{}{},
	}
	supportedClients = supportedType[clientFactory]{
		client.GrpcClient: grpcclient.NewClient,
		client.RestClient: restclient.NewClient,
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

type clientFactory func(string) (client.Client, error)

type InitArgs struct {
	ClientType string
	Wallet     wallet.Wallet
	AspUrl     string
	Seed       string
	Password   string
}

func (a InitArgs) validate() error {
	if a.Wallet == nil {
		return fmt.Errorf("missing wallet")
	}

	if len(a.ClientType) <= 0 {
		return fmt.Errorf("missing client type")
	}
	if !supportedClients.supports(a.ClientType) {
		return fmt.Errorf("client type not supported, please select one of: %s", supportedClients)
	}

	if len(a.AspUrl) <= 0 {
		return fmt.Errorf("missing asp url")
	}
	if len(a.Password) <= 0 {
		return fmt.Errorf("missing password")
	}
	return nil
}

func (a InitArgs) client() (client.Client, error) {
	factory := supportedClients[a.ClientType]
	return factory(a.AspUrl)
}

func (a InitArgs) explorer(network string) (explorer.Explorer, error) {
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
