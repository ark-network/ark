package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	singlekeywallet "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey"
	walletstore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store"
	filestore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store/file"
	inmemorystore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store/inmemory"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	DUST = 450
	// transport
	GrpcClient = client.GrpcClient
	RestClient = client.RestClient
	// wallet
	SingleKeyWallet = wallet.SingleKeyWallet
	// store
	FileStore     = store.FileStore
	InMemoryStore = store.InMemoryStore
	// explorer
	BitcoinExplorer = explorer.BitcoinExplorer
	LiquidExplorer  = explorer.LiquidExplorer
)

var (
	ErrAlreadyInitialized = fmt.Errorf("client already initialized")
	ErrNotInitialized     = fmt.Errorf("client not initialized")
)

type arkClient struct {
	*store.StoreData
	wallet   wallet.WalletService
	store    store.ConfigStore
	explorer explorer.Explorer
	client   client.ASPClient
}

func (a *arkClient) GetConfigData(
	_ context.Context,
) (*store.StoreData, error) {
	if a.StoreData == nil {
		return nil, fmt.Errorf("client sdk not initialized")
	}
	return a.StoreData, nil
}

func (a *arkClient) InitWithWallet(
	ctx context.Context, args InitWithWalletArgs,
) error {
	if err := args.validate(); err != nil {
		return fmt.Errorf("invalid args: %s", err)
	}

	clientSvc, err := getClient(
		supportedClients, args.ClientType, args.AspUrl,
	)
	if err != nil {
		return fmt.Errorf("failed to setup client: %s", err)
	}

	info, err := clientSvc.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to asp: %s", err)
	}

	explorerSvc, err := getExplorer(supportedNetworks, info.Network)
	if err != nil {
		return fmt.Errorf("failed to setup explorer: %s", err)
	}

	network := utils.NetworkFromString(info.Network)

	buf, err := hex.DecodeString(info.Pubkey)
	if err != nil {
		return fmt.Errorf("failed to parse asp pubkey: %s", err)
	}
	aspPubkey, err := secp256k1.ParsePubKey(buf)
	if err != nil {
		return fmt.Errorf("failed to parse asp pubkey: %s", err)
	}

	storeData := store.StoreData{
		AspUrl:                     args.AspUrl,
		AspPubkey:                  aspPubkey,
		WalletType:                 args.Wallet.GetType(),
		ClientType:                 args.ClientType,
		Network:                    network,
		RoundLifetime:              info.RoundLifetime,
		UnilateralExitDelay:        info.UnilateralExitDelay,
		MinRelayFee:                uint64(info.MinRelayFee),
		BoardingDescriptorTemplate: info.BoardingDescriptorTemplate,
	}
	if err := a.store.AddData(ctx, storeData); err != nil {
		return err
	}

	if _, err := args.Wallet.Create(ctx, args.Password, args.Seed); err != nil {
		//nolint:all
		a.store.CleanData(ctx)
		return err
	}

	a.StoreData = &storeData
	a.wallet = args.Wallet
	a.explorer = explorerSvc
	a.client = clientSvc

	return nil
}

func (a *arkClient) Init(
	ctx context.Context, args InitArgs,
) error {
	if err := args.validate(); err != nil {
		return fmt.Errorf("invalid args: %s", err)
	}

	clientSvc, err := getClient(
		supportedClients, args.ClientType, args.AspUrl,
	)
	if err != nil {
		return fmt.Errorf("failed to setup client: %s", err)
	}

	info, err := clientSvc.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to asp: %s", err)
	}

	explorerSvc, err := getExplorer(supportedNetworks, info.Network)
	if err != nil {
		return fmt.Errorf("failed to setup explorer: %s", err)
	}

	network := utils.NetworkFromString(info.Network)

	buf, err := hex.DecodeString(info.Pubkey)
	if err != nil {
		return fmt.Errorf("failed to parse asp pubkey: %s", err)
	}
	aspPubkey, err := secp256k1.ParsePubKey(buf)
	if err != nil {
		return fmt.Errorf("failed to parse asp pubkey: %s", err)
	}

	storeData := store.StoreData{
		AspUrl:                     args.AspUrl,
		AspPubkey:                  aspPubkey,
		WalletType:                 args.WalletType,
		ClientType:                 args.ClientType,
		Network:                    network,
		RoundLifetime:              info.RoundLifetime,
		UnilateralExitDelay:        info.UnilateralExitDelay,
		MinRelayFee:                uint64(info.MinRelayFee),
		BoardingDescriptorTemplate: info.BoardingDescriptorTemplate,
	}
	walletSvc, err := getWallet(a.store, &storeData, supportedWallets)
	if err != nil {
		return err
	}

	if err := a.store.AddData(ctx, storeData); err != nil {
		return err
	}

	if _, err := walletSvc.Create(ctx, args.Password, args.Seed); err != nil {
		//nolint:all
		a.store.CleanData(ctx)
		return err
	}

	a.StoreData = &storeData
	a.wallet = walletSvc
	a.explorer = explorerSvc
	a.client = clientSvc

	return nil
}

func (a *arkClient) Unlock(ctx context.Context, pasword string) error {
	_, err := a.wallet.Unlock(ctx, pasword)
	return err
}

func (a *arkClient) Lock(ctx context.Context, pasword string) error {
	return a.wallet.Lock(ctx, pasword)
}

func (a *arkClient) IsLocked(ctx context.Context) bool {
	return a.wallet.IsLocked()
}

func (a *arkClient) Receive(ctx context.Context) (string, string, error) {
	offchainAddr, boardingAddr, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", "", err
	}

	return offchainAddr, boardingAddr, nil
}

func (a *arkClient) ListVtxos(
	ctx context.Context,
) (spendableVtxos, spentVtxos []client.Vtxo, err error) {
	offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return
	}

	for _, addr := range offchainAddrs {
		spendable, spent, err := a.client.ListVtxos(ctx, addr)
		if err != nil {
			return nil, nil, err
		}
		spendableVtxos = append(spendableVtxos, spendable...)
		spentVtxos = append(spentVtxos, spent...)
	}

	return
}

func (a *arkClient) ping(
	ctx context.Context, paymentID string,
) func() {
	ticker := time.NewTicker(5 * time.Second)

	go func(t *time.Ticker) {
		// nolint
		a.client.Ping(ctx, paymentID)
		for range t.C {
			// nolint
			a.client.Ping(ctx, paymentID)
		}
	}(ticker)

	return ticker.Stop
}

func getClient(
	supportedClients utils.SupportedType[utils.ClientFactory], clientType, aspUrl string,
) (client.ASPClient, error) {
	factory := supportedClients[clientType]
	return factory(aspUrl)
}

func getExplorer(
	supportedNetworks utils.SupportedType[string], network string,
) (explorer.Explorer, error) {
	url, ok := supportedNetworks[network]
	if !ok {
		return nil, fmt.Errorf("invalid network")
	}

	return explorer.NewExplorer(url, utils.NetworkFromString(network)), nil
}

func getWallet(
	storeSvc store.ConfigStore, data *store.StoreData, supportedWallets utils.SupportedType[struct{}],
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
		return singlekeywallet.NewLiquidWallet(configStore, walletStore)
	}
	return singlekeywallet.NewBitcoinWallet(configStore, walletStore)
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
