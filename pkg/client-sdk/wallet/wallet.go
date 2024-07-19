package wallet

import (
	"context"
	"fmt"
	"strings"

	"github.com/ark-network/ark-sdk/explorer"
	"github.com/ark-network/ark-sdk/store"
	filestore "github.com/ark-network/ark-sdk/store/file"
	inmemorystore "github.com/ark-network/ark-sdk/store/inmemory"
	liquidwallet "github.com/ark-network/ark-sdk/wallet/singlekey/liquid"
	walletstore "github.com/ark-network/ark-sdk/wallet/singlekey/store"
	filewalletstore "github.com/ark-network/ark-sdk/wallet/singlekey/store/file"
	inmemorywalletstore "github.com/ark-network/ark-sdk/wallet/singlekey/store/inmemory"
	"github.com/ark-network/ark/common"
)

type Wallet interface {
	Create(ctx context.Context, password, key string) (seed string, err error)
	Lock(ctx context.Context, password string) (err error)
	Unlock(ctx context.Context, password string) (alreadyUnlocked bool, err error)
	GetAddresses(
		ctx context.Context,
	) (offchainAddresses, onchainAddresses, redemptionAddresses []string, err error)
	NewAddress(
		ctx context.Context, change bool,
	) (offchainAddr, onchainAddr string, err error)
	NewAddresses(
		ctx context.Context, change bool, num int,
	) (offchainAddresses, onchainAddresses []string, err error)
	SignTransaction(
		ctx context.Context, explorerSvc explorer.Explorer, tx string,
	) (singedTx string, err error)
}

type WalletFactory func(args ...interface{}) (Wallet, error)

func NewSingleKeyWallet(args ...interface{}) (Wallet, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("invalid number of args")
	}
	network, ok := args[0].(common.Network)
	if !ok {
		return nil, fmt.Errorf("invalid network")
	}
	store, ok1 := args[1].(store.Store)
	walletStore, ok2 := args[1].(walletstore.WalletStore)
	if !ok1 && !ok2 {
		return nil, fmt.Errorf("invalid store or wallet store")
	}

	if walletStore == nil {
		var err error
		switch store.(type) {
		case *inmemorystore.Store:
			walletStore, err = inmemorywalletstore.NewWalletStore(store)
		case *filestore.Store:
			walletStore, err = filewalletstore.NewWalletStore("", store)
		default:
			err = fmt.Errorf("unknown wallet store type")
		}
		if err != nil {
			return nil, err
		}
	}

	if strings.Contains(network.Name, "liquid") {
		return liquidwallet.NewWallet(walletStore)
	}
	// TODO: uncomment this line
	// return bitcoinwallet.NewWallet(walletStore)
	return nil, fmt.Errorf("bitcoin wallet not supported yet")
}
