package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	singlekeywallet "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey"
	walletstore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store"
	filestore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store/file"
	inmemorystore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store/inmemory"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/sirupsen/logrus"
)

const (
	// transport
	GrpcClient = client.GrpcClient
	RestClient = client.RestClient
	// wallet
	SingleKeyWallet = wallet.SingleKeyWallet
	// store
	FileStore     = types.FileStore
	InMemoryStore = types.InMemoryStore
	// explorer
	BitcoinExplorer = explorer.BitcoinExplorer
	LiquidExplorer  = explorer.LiquidExplorer
)

var (
	ErrAlreadyInitialized = fmt.Errorf("client already initialized")
	ErrNotInitialized     = fmt.Errorf("client not initialized")
)

var (
	defaultNetworks = utils.SupportedType[string]{
		common.Liquid.Name:         "https://blockstream.info/liquid/api",
		common.LiquidTestNet.Name:  "https://blockstream.info/liquidtestnet/api",
		common.LiquidRegTest.Name:  "http://localhost:3001",
		common.Bitcoin.Name:        "https://blockstream.info/api",
		common.BitcoinTestNet.Name: "https://blockstream.info/testnet/api",
		//common.BitcoinTestNet4.Name: "https://mempool.space/testnet4/api", //TODO uncomment once supported
		common.BitcoinSigNet.Name:    "https://blockstream.info/signet/api",
		common.BitcoinMutinyNet.Name: "https://mutinynet.com/api",
		common.BitcoinRegTest.Name:   "http://localhost:3000",
	}
)

type arkClient struct {
	*types.Config
	wallet   wallet.WalletService
	store    types.Store
	explorer explorer.Explorer
	client   client.TransportClient

	txStreamCtxCancel context.CancelFunc
}

func (a *arkClient) GetConfigData(
	_ context.Context,
) (*types.Config, error) {
	if a.Config == nil {
		return nil, fmt.Errorf("client sdk not initialized")
	}
	return a.Config, nil
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

func (a *arkClient) Dump(ctx context.Context) (string, error) {
	return a.wallet.Dump(ctx)
}

func (a *arkClient) Receive(ctx context.Context) (string, string, error) {
	offchainAddr, boardingAddr, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", "", err
	}

	return offchainAddr.Address, boardingAddr.Address, nil
}

func (a *arkClient) GetTransactionEventChannel() chan types.TransactionEvent {
	return a.store.TransactionStore().GetEventChannel()
}

func (a *arkClient) SignTransaction(ctx context.Context, tx string) (string, error) {
	return a.wallet.SignTransaction(ctx, a.explorer, tx)
}

func (a *arkClient) Stop() error {
	if a.Config.WithTransactionFeed {
		a.txStreamCtxCancel()
	}

	a.store.Close()

	return nil
}

func (a *arkClient) initWithWallet(
	ctx context.Context, args InitWithWalletArgs,
) error {
	if err := args.validate(); err != nil {
		return fmt.Errorf("invalid args: %s", err)
	}

	clientSvc, err := getClient(
		supportedClients, args.ClientType, args.ServerUrl,
	)
	if err != nil {
		return fmt.Errorf("failed to setup client: %s", err)
	}

	info, err := clientSvc.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %s", err)
	}

	explorerSvc, err := getExplorer(args.ExplorerURL, info.Network)
	if err != nil {
		return fmt.Errorf("failed to setup explorer: %s", err)
	}

	network := utils.NetworkFromString(info.Network)

	buf, err := hex.DecodeString(info.PubKey)
	if err != nil {
		return fmt.Errorf("failed to parse server pubkey: %s", err)
	}
	serverPubkey, err := secp256k1.ParsePubKey(buf)
	if err != nil {
		return fmt.Errorf("failed to parse server pubkey: %s", err)
	}

	vtxoTreeExpiryType := common.LocktimeTypeBlock
	if info.VtxoTreeExpiry >= 512 {
		vtxoTreeExpiryType = common.LocktimeTypeSecond
	}

	unilateralExitDelayType := common.LocktimeTypeBlock
	if info.UnilateralExitDelay >= 512 {
		unilateralExitDelayType = common.LocktimeTypeSecond
	}

	storeData := types.Config{
		ServerUrl:                  args.ServerUrl,
		ServerPubKey:               serverPubkey,
		WalletType:                 args.Wallet.GetType(),
		ClientType:                 args.ClientType,
		Network:                    network,
		VtxoTreeExpiry:             common.RelativeLocktime{Type: vtxoTreeExpiryType, Value: uint32(info.VtxoTreeExpiry)},
		RoundInterval:              info.RoundInterval,
		UnilateralExitDelay:        common.RelativeLocktime{Type: unilateralExitDelayType, Value: uint32(info.UnilateralExitDelay)},
		Dust:                       info.Dust,
		BoardingDescriptorTemplate: info.BoardingDescriptorTemplate,
		ForfeitAddress:             info.ForfeitAddress,
		WithTransactionFeed:        args.WithTransactionFeed,
	}
	if err := a.store.ConfigStore().AddData(ctx, storeData); err != nil {
		return err
	}

	if _, err := args.Wallet.Create(ctx, args.Password, args.Seed); err != nil {
		//nolint:all
		a.store.ConfigStore().CleanData(ctx)
		return err
	}

	a.Config = &storeData
	a.wallet = args.Wallet
	a.explorer = explorerSvc
	a.client = clientSvc

	return nil
}

func (a *arkClient) init(
	ctx context.Context, args InitArgs,
) error {
	if err := args.validate(); err != nil {
		return fmt.Errorf("invalid args: %s", err)
	}

	clientSvc, err := getClient(
		supportedClients, args.ClientType, args.ServerUrl,
	)
	if err != nil {
		return fmt.Errorf("failed to setup client: %s", err)
	}

	info, err := clientSvc.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %s", err)
	}

	explorerSvc, err := getExplorer(args.ExplorerURL, info.Network)
	if err != nil {
		return fmt.Errorf("failed to setup explorer: %s", err)
	}

	network := utils.NetworkFromString(info.Network)

	buf, err := hex.DecodeString(info.PubKey)
	if err != nil {
		return fmt.Errorf("failed to parse server pubkey: %s", err)
	}
	serverPubkey, err := secp256k1.ParsePubKey(buf)
	if err != nil {
		return fmt.Errorf("failed to parse server pubkey: %s", err)
	}

	vtxoTreeExpiryType := common.LocktimeTypeBlock
	if info.VtxoTreeExpiry >= 512 {
		vtxoTreeExpiryType = common.LocktimeTypeSecond
	}

	unilateralExitDelayType := common.LocktimeTypeBlock
	if info.UnilateralExitDelay >= 512 {
		unilateralExitDelayType = common.LocktimeTypeSecond
	}

	cfgData := types.Config{
		ServerUrl:                  args.ServerUrl,
		ServerPubKey:               serverPubkey,
		WalletType:                 args.WalletType,
		ClientType:                 args.ClientType,
		Network:                    network,
		VtxoTreeExpiry:             common.RelativeLocktime{Type: vtxoTreeExpiryType, Value: uint32(info.VtxoTreeExpiry)},
		RoundInterval:              info.RoundInterval,
		UnilateralExitDelay:        common.RelativeLocktime{Type: unilateralExitDelayType, Value: uint32(info.UnilateralExitDelay)},
		Dust:                       info.Dust,
		BoardingDescriptorTemplate: info.BoardingDescriptorTemplate,
		ExplorerURL:                args.ExplorerURL,
		ForfeitAddress:             info.ForfeitAddress,
		WithTransactionFeed:        args.WithTransactionFeed,
	}
	walletSvc, err := getWallet(a.store.ConfigStore(), &cfgData, supportedWallets)
	if err != nil {
		return err
	}

	if err := a.store.ConfigStore().AddData(ctx, cfgData); err != nil {
		return err
	}

	if _, err := walletSvc.Create(ctx, args.Password, args.Seed); err != nil {
		//nolint:all
		a.store.ConfigStore().CleanData(ctx)
		return err
	}

	a.Config = &cfgData
	a.wallet = walletSvc
	a.explorer = explorerSvc
	a.client = clientSvc

	return nil
}

func (a *arkClient) ping(
	ctx context.Context, requestID string,
) func() {
	ticker := time.NewTicker(5 * time.Second)

	go func(t *time.Ticker) {
		if err := a.client.Ping(ctx, requestID); err != nil {
			logrus.Warnf("failed to ping server: %s", err)
		}
		for range t.C {
			if err := a.client.Ping(ctx, requestID); err != nil {
				logrus.Warnf("failed to ping server: %s", err)
			}
		}
	}(ticker)

	return ticker.Stop
}

func (a *arkClient) ListVtxos(
	ctx context.Context,
) (spendableVtxos, spentVtxos []client.Vtxo, err error) {
	offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return
	}

	for _, addr := range offchainAddrs {
		spendable, spent, err := a.client.ListVtxos(ctx, addr.Address)
		if err != nil {
			return nil, nil, err
		}

		spendableVtxos = append(spendableVtxos, spendable...)
		spentVtxos = append(spentVtxos, spent...)
	}

	return
}

func getClient(
	supportedClients utils.SupportedType[utils.ClientFactory], clientType, serverUrl string,
) (client.TransportClient, error) {
	factory := supportedClients[clientType]
	return factory(serverUrl)
}

func getExplorer(explorerURL, network string) (explorer.Explorer, error) {
	if explorerURL == "" {
		var ok bool
		if explorerURL, ok = defaultNetworks[network]; !ok {
			return nil, fmt.Errorf("invalid network")
		}
	}
	return explorer.NewExplorer(explorerURL, utils.NetworkFromString(network)), nil
}

func getWallet(
	configStore types.ConfigStore, data *types.Config, supportedWallets utils.SupportedType[struct{}],
) (wallet.WalletService, error) {
	switch data.WalletType {
	case wallet.SingleKeyWallet:
		return getSingleKeyWallet(configStore, data.Network.Name)
	default:
		return nil, fmt.Errorf(
			"unsuported wallet type '%s', please select one of: %s",
			data.WalletType, supportedWallets,
		)
	}
}

func getSingleKeyWallet(
	configStore types.ConfigStore, network string,
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
	case types.InMemoryStore:
		return inmemorystore.NewWalletStore()
	case types.FileStore:
		return filestore.NewWalletStore(datadir)
	default:
		return nil, fmt.Errorf("unknown wallet store type")
	}
}

func getCreatedAtFromExpiry(vtxoTreeExpiry common.RelativeLocktime, expiry time.Time) time.Time {
	return expiry.Add(-time.Duration(vtxoTreeExpiry.Seconds()) * time.Second)
}

func filterByOutpoints(vtxos []client.Vtxo, outpoints []client.Outpoint) []client.Vtxo {
	filtered := make([]client.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		for _, outpoint := range outpoints {
			if vtxo.Outpoint.Equals(outpoint) {
				filtered = append(filtered, vtxo)
			}
		}
	}
	return filtered
}
