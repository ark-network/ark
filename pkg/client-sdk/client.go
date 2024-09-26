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
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/store/domain"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	singlekeywallet "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey"
	walletstore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store"
	filestore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store/file"
	inmemorystore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store/inmemory"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
)

const (
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

var (
	defaultNetworks = utils.SupportedType[string]{
		common.Liquid.Name:         "https://blockstream.info/liquid/api",
		common.LiquidTestNet.Name:  "https://blockstream.info/liquidtestnet/api",
		common.LiquidRegTest.Name:  "http://localhost:3001",
		common.Bitcoin.Name:        "https://blockstream.info/api",
		common.BitcoinTestNet.Name: "https://blockstream.info/testnet/api",
		common.BitcoinRegTest.Name: "http://localhost:3000",
		common.BitcoinSigNet.Name:  "https://mutinynet.com/api",
	}
)

const (
	vtxoSpent   spent = true
	vtxoUnspent spent = false
)

type spent bool

type arkClient struct {
	ctxListenVtxo       context.Context
	ctxCancelListenVtxo context.CancelFunc

	*domain.ConfigData
	sdkRepository domain.SdkRepository
	wallet        wallet.WalletService
	explorer      explorer.Explorer
	client        client.ASPClient

	sdkInitialized  bool
	listeningToVtxo bool
}

func (a *arkClient) GetConfigData(
	_ context.Context,
) (*domain.ConfigData, error) {
	if a.ConfigData == nil {
		return nil, fmt.Errorf("client sdk not initialized")
	}
	return a.ConfigData, nil
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

	explorerSvc, err := getExplorer(args.ExplorerURL, info.Network)
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

	storeData := domain.ConfigData{
		AspUrl:                     args.AspUrl,
		AspPubkey:                  aspPubkey,
		WalletType:                 args.Wallet.GetType(),
		ClientType:                 args.ClientType,
		Network:                    network,
		RoundLifetime:              info.RoundLifetime,
		RoundInterval:              info.RoundInterval,
		UnilateralExitDelay:        info.UnilateralExitDelay,
		Dust:                       info.Dust,
		BoardingDescriptorTemplate: info.BoardingDescriptorTemplate,
	}
	if err := a.sdkRepository.ConfigRepository().AddData(ctx, storeData); err != nil {
		return err
	}

	if _, err := args.Wallet.Create(ctx, args.Password, args.Seed); err != nil {
		//nolint:all
		a.sdkRepository.ConfigRepository().CleanData(ctx)
		return err
	}

	a.ConfigData = &storeData
	a.wallet = args.Wallet
	a.explorer = explorerSvc
	a.client = clientSvc
	a.sdkInitialized = true

	return nil
}

func (a *arkClient) GetTransactionHistory(
	ctx context.Context,
) ([]domain.Transaction, error) {
	return a.sdkRepository.AppDataRepository().TransactionRepository().GetAll(ctx)
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

	explorerSvc, err := getExplorer(args.ExplorerURL, info.Network)
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

	storeData := domain.ConfigData{
		AspUrl:                     args.AspUrl,
		AspPubkey:                  aspPubkey,
		WalletType:                 args.WalletType,
		ClientType:                 args.ClientType,
		Network:                    network,
		RoundLifetime:              info.RoundLifetime,
		RoundInterval:              info.RoundInterval,
		UnilateralExitDelay:        info.UnilateralExitDelay,
		Dust:                       info.Dust,
		BoardingDescriptorTemplate: info.BoardingDescriptorTemplate,
		ExplorerURL:                args.ExplorerURL,
	}
	walletSvc, err := getWallet(a.sdkRepository.ConfigRepository(), &storeData, supportedWallets)
	if err != nil {
		return err
	}

	if err := a.sdkRepository.ConfigRepository().AddData(ctx, storeData); err != nil {
		return err
	}

	if _, err := walletSvc.Create(ctx, args.Password, args.Seed); err != nil {
		//nolint:all
		a.sdkRepository.ConfigRepository().CleanData(ctx)
		return err
	}

	a.ConfigData = &storeData
	a.wallet = walletSvc
	a.explorer = explorerSvc
	a.client = clientSvc
	a.sdkInitialized = true

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

func (a *arkClient) Dump(ctx context.Context) (string, error) {
	return a.wallet.Dump(ctx)
}

func (a *arkClient) Receive(ctx context.Context) (string, string, error) {
	offchainAddr, boardingAddr, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", "", err
	}

	return offchainAddr, boardingAddr, nil
}

func (a *arkClient) Close() error {
	if a.listeningToVtxo {
		a.ctxCancelListenVtxo()
	}

	if err := a.sdkRepository.AppDataRepository().Stop(); err != nil {
		return err
	}

	return nil
}

func (a *arkClient) ping(
	ctx context.Context, paymentID string,
) func() {
	ticker := time.NewTicker(5 * time.Second)

	go func(t *time.Ticker) {
		if _, err := a.client.Ping(ctx, paymentID); err != nil {
			log.Warnf("failed to ping asp: %s", err)
		}
		for range t.C {
			if _, err := a.client.Ping(ctx, paymentID); err != nil {
				log.Warnf("failed to ping asp: %s", err)
			}
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
	storeSvc domain.ConfigRepository, data *domain.ConfigData, supportedWallets utils.SupportedType[struct{}],
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
	configStore domain.ConfigRepository, network string,
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

func getCreatedAtFromExpiry(roundLifetime int64, expiry time.Time) time.Time {
	return expiry.Add(-time.Duration(roundLifetime) * time.Second)
}

func findNewTxs(oldTxs, newTxs []domain.Transaction) ([]domain.Transaction, error) {
	newTxsMap := make(map[string]domain.Transaction)
	for _, tx := range newTxs {
		newTxsMap[tx.Key()] = tx
	}

	oldTxsMap := make(map[string]domain.Transaction)
	for _, tx := range oldTxs {
		oldTxsMap[tx.Key()] = tx
	}

	var result []domain.Transaction
	for _, tx := range newTxs {
		if _, ok := oldTxsMap[tx.Key()]; !ok {
			result = append(result, tx)
		}
	}

	return result, nil
}

func updateBoardingTxsState(
	allBoardingTxs, oldBoardingTxs []domain.Transaction,
) ([]domain.Transaction, []domain.Transaction) {
	var newBoardingTxs []domain.Transaction
	var updatedOldBoardingTxs []domain.Transaction

	newTxsMap := make(map[string]bool)
	for _, newTx := range allBoardingTxs {
		newTxsMap[newTx.BoardingTxid] = true
	}

	for _, oldTx := range oldBoardingTxs {
		if !newTxsMap[oldTx.BoardingTxid] {
			oldTx.IsPending = false
			updatedOldBoardingTxs = append(updatedOldBoardingTxs, oldTx)
		}
	}

	for _, newTx := range allBoardingTxs {
		if !containsTx(oldBoardingTxs, newTx.BoardingTxid) {
			newBoardingTxs = append(newBoardingTxs, newTx)
		}
	}

	return newBoardingTxs, updatedOldBoardingTxs
}

func containsTx(txs []domain.Transaction, txid string) bool {
	for _, tx := range txs {
		if tx.BoardingTxid == txid {
			return true
		}
	}
	return false
}
