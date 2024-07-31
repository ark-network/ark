package arksdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark-sdk/client"
	"github.com/ark-network/ark-sdk/explorer"
	"github.com/ark-network/ark-sdk/internal/utils"
	"github.com/ark-network/ark-sdk/store"
	"github.com/ark-network/ark-sdk/wallet"
	walletstore "github.com/ark-network/ark-sdk/wallet/singlekey/store"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
	"github.com/vulpemventures/go-elements/transaction"
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

type ArkClient interface {
	Init(ctx context.Context, args InitArgs) error
	InitWithWallet(ctx context.Context, args InitWithWalletArgs) error
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context, password string) error
	Balance(ctx context.Context, computeExpiryDetails bool) (*Balance, error)
	Onboard(ctx context.Context, amount uint64) (string, error)
	Receive(ctx context.Context) (string, string, error)
	SendOnChain(ctx context.Context, receivers []Receiver) (string, error)
	SendOffChain(
		ctx context.Context, withExpiryCoinselect bool, receivers []Receiver,
	) (string, error)
	UnilateralRedeem(ctx context.Context) error
	CollaborativeRedeem(
		ctx context.Context, addr string, amount uint64, withExpiryCoinselect bool,
	) (string, error)
	GetConfigData(ctx context.Context) (*store.StoreData, error)
	GetWalletStore(ctx context.Context, password string) (walletstore.WalletStore, error)
}

type arkClient struct {
	*store.StoreData
	wallet   wallet.WalletService
	store    store.ConfigStore
	explorer explorer.Explorer
	client   client.ASPClient
}

func New(storeSvc store.ConfigStore) (ArkClient, error) {
	data, err := storeSvc.GetData(context.Background())
	if err != nil {
		return nil, err
	}
	if data != nil {
		return nil, ErrAlreadyInitialized
	}

	return &arkClient{store: storeSvc}, nil
}

func Load(storeSvc store.ConfigStore) (ArkClient, error) {
	if storeSvc == nil {
		return nil, fmt.Errorf("missin store service")
	}

	data, err := storeSvc.GetData(context.Background())
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, ErrNotInitialized
	}

	clientSvc, err := utils.GetClient(
		supportedClients, data.ClientType, data.AspUrl,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup transport client: %s", err)
	}

	explorerSvc, err := utils.GetExplorer(supportedNetworks, data.Network.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to setup explorer: %s", err)
	}

	walletSvc, err := utils.GetWallet(storeSvc, data, supportedWallets)
	if err != nil {
		return nil, fmt.Errorf("faile to setup wallet: %s", err)
	}

	return &arkClient{data, walletSvc, storeSvc, explorerSvc, clientSvc}, nil
}

func LoadWithWallet(
	storeSvc store.ConfigStore, walletSvc wallet.WalletService,
) (ArkClient, error) {
	if storeSvc == nil {
		return nil, fmt.Errorf("missin store service")
	}
	if walletSvc == nil {
		return nil, fmt.Errorf("missin wallet service")
	}

	data, err := storeSvc.GetData(context.Background())
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, ErrNotInitialized
	}

	clientSvc, err := utils.GetClient(
		supportedClients, data.ClientType, data.AspUrl,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup transport client: %s", err)
	}

	explorerSvc, err := utils.GetExplorer(supportedNetworks, data.Network.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to setup explorer: %s", err)
	}

	return &arkClient{data, walletSvc, storeSvc, explorerSvc, clientSvc}, nil
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

	clientSvc, err := utils.GetClient(
		supportedClients, args.ClientType, args.AspUrl,
	)
	if err != nil {
		return fmt.Errorf("failed to setup client: %s", err)
	}

	resp, err := clientSvc.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to asp: %s", err)
	}

	explorerSvc, err := utils.GetExplorer(supportedNetworks, resp.GetNetwork())
	if err != nil {
		return fmt.Errorf("failed to setup explorer: %s", err)
	}

	network := utils.NetworkFromString(resp.GetNetwork())

	buf, err := hex.DecodeString(resp.GetPubkey())
	if err != nil {
		return fmt.Errorf("failed to parse asp pubkey: %s", err)
	}
	aspPubkey, err := secp256k1.ParsePubKey(buf)
	if err != nil {
		return fmt.Errorf("failed to parse asp pubkey: %s", err)
	}

	storeData := store.StoreData{
		AspUrl:              args.AspUrl,
		AspPubkey:           aspPubkey,
		WalletType:          args.Wallet.GetType(),
		ClientType:          args.ClientType,
		Network:             network,
		RoundLifetime:       resp.GetRoundLifetime(),
		UnilateralExitDelay: resp.GetUnilateralExitDelay(),
		MinRelayFee:         uint64(resp.GetMinRelayFee()),
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

	clientSvc, err := utils.GetClient(
		supportedClients, args.ClientType, args.AspUrl,
	)
	if err != nil {
		return fmt.Errorf("failed to setup client: %s", err)
	}

	resp, err := clientSvc.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to asp: %s", err)
	}

	explorerSvc, err := utils.GetExplorer(supportedNetworks, resp.GetNetwork())
	if err != nil {
		return fmt.Errorf("failed to setup explorer: %s", err)
	}

	network := utils.NetworkFromString(resp.GetNetwork())

	buf, err := hex.DecodeString(resp.GetPubkey())
	if err != nil {
		return fmt.Errorf("failed to parse asp pubkey: %s", err)
	}
	aspPubkey, err := secp256k1.ParsePubKey(buf)
	if err != nil {
		return fmt.Errorf("failed to parse asp pubkey: %s", err)
	}

	storeData := store.StoreData{
		AspUrl:              args.AspUrl,
		AspPubkey:           aspPubkey,
		WalletType:          args.WalletType,
		ClientType:          args.ClientType,
		Network:             network,
		RoundLifetime:       resp.GetRoundLifetime(),
		UnilateralExitDelay: resp.GetUnilateralExitDelay(),
		MinRelayFee:         uint64(resp.GetMinRelayFee()),
	}
	walletSvc, err := utils.GetWallet(a.store, &storeData, supportedWallets)
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

func (a *arkClient) Balance(
	ctx context.Context, computeExpiryDetails bool,
) (*Balance, error) {
	offchainAddrs, onchainAddrs, redeemAddrs, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	wg := &sync.WaitGroup{}
	wg.Add(3 * len(offchainAddrs))

	chRes := make(chan balanceRes, 3)
	for i := range offchainAddrs {
		offchainAddr := offchainAddrs[i]
		onchainAddr := onchainAddrs[i]
		redeemAddr := redeemAddrs[i]
		go func(addr string) {
			defer wg.Done()
			balance, amountByExpiration, err := a.client.GetOffchainBalance(
				ctx, addr, a.explorer,
			)
			if err != nil {
				chRes <- balanceRes{err: err}
				return
			}

			chRes <- balanceRes{
				offchainBalance:             balance,
				offchainBalanceByExpiration: amountByExpiration,
			}
		}(offchainAddr)

		go func(addr string) {
			defer wg.Done()
			balance, err := a.explorer.GetBalance(addr)
			if err != nil {
				chRes <- balanceRes{err: err}
				return
			}
			chRes <- balanceRes{onchainSpendableBalance: balance}
		}(onchainAddr)

		go func(addr string) {
			defer wg.Done()

			spendableBalance, lockedBalance, err := a.explorer.GetRedeemedVtxosBalance(
				addr, a.UnilateralExitDelay,
			)
			if err != nil {
				chRes <- balanceRes{err: err}
				return
			}

			chRes <- balanceRes{
				onchainSpendableBalance: spendableBalance,
				onchainLockedBalance:    lockedBalance,
				err:                     err,
			}
		}(redeemAddr)
	}

	wg.Wait()

	lockedOnchainBalance := []LockedOnchainBalance{}
	details := make([]VtxoDetails, 0)
	offchainBalance, onchainBalance := uint64(0), uint64(0)
	nextExpiration := int64(0)
	count := 0
	for res := range chRes {
		if res.err != nil {
			return nil, res.err
		}
		if res.offchainBalance > 0 {
			offchainBalance = res.offchainBalance
		}
		if res.onchainSpendableBalance > 0 {
			onchainBalance += res.onchainSpendableBalance
		}
		if res.offchainBalanceByExpiration != nil {
			for timestamp, amount := range res.offchainBalanceByExpiration {
				if nextExpiration == 0 || timestamp < nextExpiration {
					nextExpiration = timestamp
				}

				fancyTime := time.Unix(timestamp, 0).Format(time.RFC3339)
				details = append(
					details,
					VtxoDetails{
						ExpiryTime: fancyTime,
						Amount:     amount,
					},
				)
			}
		}
		if res.onchainLockedBalance != nil {
			for timestamp, amount := range res.onchainLockedBalance {
				fancyTime := time.Unix(timestamp, 0).Format(time.RFC3339)
				lockedOnchainBalance = append(
					lockedOnchainBalance,
					LockedOnchainBalance{
						SpendableAt: fancyTime,
						Amount:      amount,
					},
				)
			}
		}

		count++
		if count == 3 {
			break
		}
	}

	fancyTimeExpiration := ""
	if nextExpiration != 0 {
		t := time.Unix(nextExpiration, 0)
		if t.Before(time.Now().Add(48 * time.Hour)) {
			// print the duration instead of the absolute time
			until := time.Until(t)
			seconds := math.Abs(until.Seconds())
			minutes := math.Abs(until.Minutes())
			hours := math.Abs(until.Hours())

			if hours < 1 {
				if minutes < 1 {
					fancyTimeExpiration = fmt.Sprintf("%d seconds", int(seconds))
				} else {
					fancyTimeExpiration = fmt.Sprintf("%d minutes", int(minutes))
				}
			} else {
				fancyTimeExpiration = fmt.Sprintf("%d hours", int(hours))
			}
		} else {
			fancyTimeExpiration = t.Format(time.RFC3339)
		}
	}

	response := &Balance{
		OnchainBalance: OnchainBalance{
			SpendableAmount: onchainBalance,
			LockedAmount:    lockedOnchainBalance,
		},
		OffchainBalance: OffchainBalance{
			Total:          offchainBalance,
			NextExpiration: fancyTimeExpiration,
			Details:        details,
		},
	}

	return response, nil
}

func (a *arkClient) Onboard(
	ctx context.Context, amount uint64,
) (string, error) {
	if amount <= 0 {
		return "", fmt.Errorf("invalid amount to onboard %d", amount)
	}

	offchainAddr, _, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", err
	}

	net := a.explorer.GetNetwork()
	_, userPubkey, aspPubkey, _ := common.DecodeAddress(offchainAddr)
	userPubkeyStr := hex.EncodeToString(userPubkey.SerializeCompressed())
	congestionTreeLeaf := tree.Receiver{
		Pubkey: userPubkeyStr,
		Amount: amount,
	}

	treeFactoryFn, sharedOutputScript, sharedOutputAmount, err := tree.CraftCongestionTree(
		net.AssetID,
		aspPubkey,
		[]tree.Receiver{congestionTreeLeaf},
		a.MinRelayFee,
		a.RoundLifetime,
		a.UnilateralExitDelay,
	)
	if err != nil {
		return "", err
	}

	pay, err := payment.FromScript(sharedOutputScript, &net, nil)
	if err != nil {
		return "", err
	}

	addr, err := pay.TaprootAddress()
	if err != nil {
		return "", err
	}

	onchainReceiver := Receiver{
		To:     addr,
		Amount: sharedOutputAmount,
	}

	pset, err := a.sendOnchain(ctx, []Receiver{onchainReceiver})
	if err != nil {
		return "", err
	}

	ptx, _ := psetv2.NewPsetFromBase64(pset)
	utx, _ := ptx.UnsignedTx()
	txid := utx.TxHash().String()

	congestionTree, err := treeFactoryFn(psetv2.InputArgs{
		Txid:    txid,
		TxIndex: 0,
	})
	if err != nil {
		return "", err
	}

	if _, err = a.client.Onboard(ctx, &arkv1.OnboardRequest{
		BoardingTx:     pset,
		CongestionTree: utils.CastCongestionTree(congestionTree),
		UserPubkey:     userPubkeyStr,
	}); err != nil {
		return "", err
	}

	return txid, nil
}

func (a *arkClient) SendOnChain(
	ctx context.Context, receivers []Receiver,
) (string, error) {
	for _, receiver := range receivers {
		if !receiver.IsOnChain() {
			return "", fmt.Errorf("invalid receiver address '%s': must be onchain", receiver.To)
		}
	}

	return a.sendOnchain(ctx, receivers)
}

func (a *arkClient) SendOffChain(
	ctx context.Context,
	withExpiryCoinselect bool, receivers []Receiver,
) (string, error) {
	for _, receiver := range receivers {
		if receiver.IsOnChain() {
			return "", fmt.Errorf("invalid receiver address '%s': must be offchain", receiver.To)
		}
	}

	return a.sendOffchain(ctx, withExpiryCoinselect, receivers)
}

func (a *arkClient) UnilateralRedeem(ctx context.Context) error {
	if a.wallet.IsLocked() {
		return fmt.Errorf("wallet is locked")
	}

	offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return err
	}

	vtxos := make([]*client.Vtxo, 0)
	for _, offchainAddr := range offchainAddrs {
		fetchedVtxos, err := a.client.GetSpendableVtxos(ctx, offchainAddr, nil)
		if err != nil {
			return err
		}
		vtxos = append(vtxos, fetchedVtxos...)
	}

	totalVtxosAmount := uint64(0)
	for _, vtxo := range vtxos {
		totalVtxosAmount += vtxo.Amount
	}

	// transactionsMap avoid duplicates
	transactionsMap := make(map[string]struct{}, 0)
	transactions := make([]string, 0)

	redeemBranches, err := a.client.GetRedeemBranches(ctx, vtxos, a.explorer)
	if err != nil {
		return err
	}

	for _, branch := range redeemBranches {
		branchTxs, err := branch.RedeemPath()
		if err != nil {
			return err
		}

		for _, txHex := range branchTxs {
			if _, ok := transactionsMap[txHex]; !ok {
				transactions = append(transactions, txHex)
				transactionsMap[txHex] = struct{}{}
			}
		}
	}

	for i, txHex := range transactions {
		for {
			txid, err := a.explorer.Broadcast(txHex)
			if err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "bad-txns-inputs-missingorspent") {
					time.Sleep(1 * time.Second)
				} else {
					return err
				}
			}

			if len(txid) > 0 {
				log.Infof("(%d/%d) broadcasted tx %s", i+1, len(transactions), txid)
				break
			}
		}
	}

	return nil
}

func (a *arkClient) CollaborativeRedeem(
	ctx context.Context,
	addr string, amount uint64, withExpiryCoinselect bool,
) (string, error) {
	if a.wallet.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

	if _, err := address.ToOutputScript(addr); err != nil {
		return "", fmt.Errorf("invalid onchain address")
	}

	addrNet, err := address.NetworkForAddress(addr)
	if err != nil {
		return "", fmt.Errorf("invalid onchain address: unknown network")
	}
	net := a.explorer.GetNetwork()
	if net.Name != addrNet.Name {
		return "", fmt.Errorf("invalid onchain address: must be for %s network", net.Name)
	}

	if isConf, _ := address.IsConfidential(addr); isConf {
		info, _ := address.FromConfidential(addr)
		addr = info.Address
	}

	offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}

	receivers := []*arkv1.Output{
		{
			Address: addr,
			Amount:  amount,
		},
	}

	var explorerSvc explorer.Explorer
	if withExpiryCoinselect {
		explorerSvc = a.explorer
	}
	vtxos := make([]*client.Vtxo, 0)
	for _, offchainAddr := range offchainAddrs {
		fetchedVtxos, err := a.client.GetSpendableVtxos(ctx, offchainAddr, explorerSvc)
		if err != nil {
			return "", err
		}
		vtxos = append(vtxos, fetchedVtxos...)
	}

	selectedCoins, changeAmount, err := utils.CoinSelect(
		vtxos, amount, DUST, withExpiryCoinselect,
	)
	if err != nil {
		return "", err
	}

	if changeAmount > 0 {
		offchainAddr, _, err := a.wallet.NewAddress(ctx, true)
		if err != nil {
			return "", err
		}
		receivers = append(receivers, &arkv1.Output{
			Address: offchainAddr,
			Amount:  changeAmount,
		})
	}

	inputs := make([]*arkv1.Input, 0, len(selectedCoins))

	for _, coin := range selectedCoins {
		inputs = append(inputs, &arkv1.Input{
			Txid: coin.Txid,
			Vout: coin.VOut,
		})
	}

	registerResponse, err := a.client.RegisterPayment(ctx, &arkv1.RegisterPaymentRequest{
		Inputs: inputs,
	})
	if err != nil {
		return "", err
	}

	_, err = a.client.ClaimPayment(ctx, &arkv1.ClaimPaymentRequest{
		Id:      registerResponse.GetId(),
		Outputs: receivers,
	})
	if err != nil {
		return "", err
	}

	poolTxID, err := a.handleRoundStream(
		ctx,
		registerResponse.GetId(),
		selectedCoins,
		receivers,
	)
	if err != nil {
		return "", err
	}

	return poolTxID, nil
}

func (a *arkClient) sendOnchain(
	ctx context.Context, receivers []Receiver,
) (string, error) {
	if a.wallet.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

	pset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return "", err
	}
	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return "", err
	}

	net := a.explorer.GetNetwork()

	targetAmount := uint64(0)
	for _, receiver := range receivers {
		targetAmount += receiver.Amount
		if receiver.Amount < DUST {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount, DUST)
		}

		script, err := address.ToOutputScript(receiver.To)
		if err != nil {
			return "", err
		}

		if err := updater.AddOutputs([]psetv2.OutputArgs{
			{
				Asset:  net.AssetID,
				Amount: receiver.Amount,
				Script: script,
			},
		}); err != nil {
			return "", err
		}
	}

	utxos, delayedUtxos, change, err := a.coinSelectOnchain(
		ctx, targetAmount, nil,
	)
	if err != nil {
		return "", err
	}

	if err := a.addInputs(ctx, updater, utxos, delayedUtxos, net); err != nil {
		return "", err
	}

	if change > 0 {
		_, changeAddr, err := a.wallet.NewAddress(ctx, true)
		if err != nil {
			return "", err
		}

		changeScript, err := address.ToOutputScript(changeAddr)
		if err != nil {
			return "", err
		}

		if err := updater.AddOutputs([]psetv2.OutputArgs{
			{
				Asset:  net.AssetID,
				Amount: change,
				Script: changeScript,
			},
		}); err != nil {
			return "", err
		}
	}

	utx, err := pset.UnsignedTx()
	if err != nil {
		return "", err
	}

	vBytes := utx.VirtualSize()
	feeAmount := uint64(math.Ceil(float64(vBytes) * 0.5))

	if change > feeAmount {
		updater.Pset.Outputs[len(updater.Pset.Outputs)-1].Value = change - feeAmount
	} else if change == feeAmount {
		updater.Pset.Outputs = updater.Pset.Outputs[:len(updater.Pset.Outputs)-1]
	} else { // change < feeAmount
		if change > 0 {
			updater.Pset.Outputs = updater.Pset.Outputs[:len(updater.Pset.Outputs)-1]
		}
		// reselect the difference
		selected, delayedSelected, newChange, err := a.coinSelectOnchain(
			ctx, feeAmount-change, append(utxos, delayedUtxos...),
		)
		if err != nil {
			return "", err
		}

		if err := a.addInputs(ctx, updater, selected, delayedSelected, net); err != nil {
			return "", err
		}

		if newChange > 0 {
			_, changeAddr, err := a.wallet.NewAddress(ctx, true)
			if err != nil {
				return "", err
			}

			changeScript, err := address.ToOutputScript(changeAddr)
			if err != nil {
				return "", err
			}

			if err := updater.AddOutputs([]psetv2.OutputArgs{
				{
					Asset:  net.AssetID,
					Amount: newChange,
					Script: changeScript,
				},
			}); err != nil {
				return "", err
			}
		}
	}

	if err := updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  net.AssetID,
			Amount: feeAmount,
		},
	}); err != nil {
		return "", err
	}

	tx, err := pset.ToBase64()
	if err != nil {
		return "", err
	}
	signedTx, err := a.wallet.SignTransaction(ctx, a.explorer, tx)
	if err != nil {
		return "", err
	}

	pset, err = psetv2.NewPsetFromBase64(signedTx)
	if err != nil {
		return "", err
	}

	if err := psetv2.FinalizeAll(pset); err != nil {
		return "", err
	}

	return pset.ToBase64()
}

func (a *arkClient) sendOffchain(
	ctx context.Context, withExpiryCoinselect bool, receivers []Receiver,
) (string, error) {
	if a.wallet.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

	offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}
	if len(offchainAddrs) <= 0 {
		return "", fmt.Errorf("no funds detected")
	}

	_, _, aspPubKey, err := common.DecodeAddress(offchainAddrs[0])
	if err != nil {
		return "", err
	}

	receiversOutput := make([]*arkv1.Output, 0)
	sumOfReceivers := uint64(0)

	for _, receiver := range receivers {
		_, _, aspKey, err := common.DecodeAddress(receiver.To)
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		if !bytes.Equal(
			aspPubKey.SerializeCompressed(), aspKey.SerializeCompressed(),
		) {
			return "", fmt.Errorf("invalid receiver address '%s': must be associated with the connected service provider", receiver.To)
		}

		if receiver.Amount < DUST {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount, DUST)
		}

		receiversOutput = append(receiversOutput, &arkv1.Output{
			Address: receiver.To,
			Amount:  receiver.Amount,
		})
		sumOfReceivers += receiver.Amount
	}

	var explorerSvc explorer.Explorer
	if withExpiryCoinselect {
		explorerSvc = a.explorer
	}

	vtxos := make([]*client.Vtxo, 0)
	for _, offchainAddr := range offchainAddrs {
		fetchedVtxos, err := a.client.GetSpendableVtxos(ctx, offchainAddr, explorerSvc)
		if err != nil {
			return "", err
		}
		vtxos = append(vtxos, fetchedVtxos...)
	}

	selectedCoins, changeAmount, err := utils.CoinSelect(
		vtxos, sumOfReceivers, DUST, withExpiryCoinselect,
	)
	if err != nil {
		return "", err
	}

	if changeAmount > 0 {
		offchainAddr, _, err := a.wallet.NewAddress(ctx, true)
		if err != nil {
			return "", err
		}
		changeReceiver := &arkv1.Output{
			Address: offchainAddr,
			Amount:  changeAmount,
		}
		receiversOutput = append(receiversOutput, changeReceiver)
	}

	inputs := make([]*arkv1.Input, 0, len(selectedCoins))

	for _, coin := range selectedCoins {
		inputs = append(inputs, &arkv1.Input{
			Txid: coin.Txid,
			Vout: coin.VOut,
		})
	}

	registerResponse, err := a.client.RegisterPayment(
		ctx, &arkv1.RegisterPaymentRequest{Inputs: inputs},
	)
	if err != nil {
		return "", err
	}

	_, err = a.client.ClaimPayment(ctx, &arkv1.ClaimPaymentRequest{
		Id:      registerResponse.GetId(),
		Outputs: receiversOutput,
	})
	if err != nil {
		return "", err
	}

	log.Infof("payment registered with id: %s", registerResponse.GetId())

	poolTxID, err := a.handleRoundStream(
		ctx,
		registerResponse.GetId(),
		selectedCoins,
		receiversOutput,
	)
	if err != nil {
		return "", err
	}

	return poolTxID, nil
}

func (a *arkClient) addInputs(
	ctx context.Context, updater *psetv2.Updater, utxos, delayedUtxos []explorer.Utxo, net network.Network,
) error {
	offchainAddr, onchainAddr, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return err
	}

	_, userPubkey, aspPubkey, _ := common.DecodeAddress(offchainAddr)

	changeScript, err := address.ToOutputScript(onchainAddr)
	if err != nil {
		return err
	}

	for _, utxo := range utxos {
		if err := updater.AddInputs([]psetv2.InputArgs{
			{
				Txid:    utxo.Txid,
				TxIndex: utxo.Vout,
			},
		}); err != nil {
			return err
		}

		assetID, err := elementsutil.AssetHashToBytes(utxo.Asset)
		if err != nil {
			return err
		}

		value, err := elementsutil.ValueToBytes(utxo.Amount)
		if err != nil {
			return err
		}

		witnessUtxo := transaction.TxOutput{
			Asset:  assetID,
			Value:  value,
			Script: changeScript,
			Nonce:  []byte{0x00},
		}

		if err := updater.AddInWitnessUtxo(
			len(updater.Pset.Inputs)-1, &witnessUtxo,
		); err != nil {
			return err
		}
	}

	if len(delayedUtxos) > 0 {
		_, leafProof, script, _, err := tree.ComputeVtxoTaprootScript(
			userPubkey, aspPubkey, uint(a.UnilateralExitDelay), net,
		)
		if err != nil {
			return err
		}

		for _, utxo := range delayedUtxos {
			if err := addVtxoInput(
				updater,
				psetv2.InputArgs{
					Txid:    utxo.Txid,
					TxIndex: utxo.Vout,
				},
				uint(a.UnilateralExitDelay),
				leafProof,
			); err != nil {
				return err
			}

			assetID, err := elementsutil.AssetHashToBytes(utxo.Asset)
			if err != nil {
				return err
			}

			value, err := elementsutil.ValueToBytes(utxo.Amount)
			if err != nil {
				return err
			}

			witnessUtxo := transaction.NewTxOutput(assetID, value, script)

			if err := updater.AddInWitnessUtxo(
				len(updater.Pset.Inputs)-1, witnessUtxo,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

func addVtxoInput(
	updater *psetv2.Updater, inputArgs psetv2.InputArgs, exitDelay uint,
	tapLeafProof *taproot.TapscriptElementsProof,
) error {
	sequence, err := common.BIP68EncodeAsNumber(exitDelay)
	if err != nil {
		return nil
	}

	nextInputIndex := len(updater.Pset.Inputs)
	if err := updater.AddInputs([]psetv2.InputArgs{inputArgs}); err != nil {
		return err
	}

	updater.Pset.Inputs[nextInputIndex].Sequence = sequence

	return updater.AddInTapLeafScript(
		nextInputIndex,
		psetv2.NewTapLeafScript(
			*tapLeafProof,
			tree.UnspendableKey(),
		),
	)
}

type Receiver struct {
	To     string `json:"to"`
	Amount uint64 `json:"amount"`
}

func (r *Receiver) IsOnChain() bool {
	_, err := address.ToOutputScript(r.To)
	return err == nil
}

func (a *arkClient) Receive(ctx context.Context) (string, string, error) {
	offchainAddr, onchainAddr, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", "", err
	}

	return offchainAddr, onchainAddr, nil
}

func (a *arkClient) coinSelectOnchain(
	ctx context.Context, targetAmount uint64, exclude []explorer.Utxo,
) ([]explorer.Utxo, []explorer.Utxo, uint64, error) {
	offchainAddrs, onchainAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	net := a.explorer.GetNetwork()

	fetchedUtxos := make([]explorer.Utxo, 0)
	for _, onchainAddr := range onchainAddrs {
		utxos, err := a.explorer.GetUtxos(onchainAddr)
		if err != nil {
			return nil, nil, 0, err
		}
		fetchedUtxos = append(fetchedUtxos, utxos...)
	}

	utxos := make([]explorer.Utxo, 0)
	selectedAmount := uint64(0)
	for _, utxo := range fetchedUtxos {
		if selectedAmount >= targetAmount {
			break
		}

		for _, excluded := range exclude {
			if utxo.Txid == excluded.Txid && utxo.Vout == excluded.Vout {
				continue
			}
		}

		utxos = append(utxos, utxo)
		selectedAmount += utxo.Amount
	}

	if selectedAmount >= targetAmount {
		return utxos, nil, selectedAmount - targetAmount, nil
	}

	fetchedUtxos = make([]explorer.Utxo, 0)
	for _, offchainAddr := range offchainAddrs {
		_, userPubkey, aspPubkey, _ := common.DecodeAddress(offchainAddr)
		_, _, _, addr, err := tree.ComputeVtxoTaprootScript(
			userPubkey, aspPubkey, uint(a.UnilateralExitDelay), net,
		)
		if err != nil {
			return nil, nil, 0, err
		}

		utxos, err = a.explorer.GetUtxos(addr)
		if err != nil {
			return nil, nil, 0, err
		}
		fetchedUtxos = append(fetchedUtxos, utxos...)
	}

	delayedUtxos := make([]explorer.Utxo, 0)
	for _, utxo := range fetchedUtxos {
		if selectedAmount >= targetAmount {
			break
		}

		availableAt := time.Unix(utxo.Status.Blocktime, 0).Add(
			time.Duration(a.UnilateralExitDelay) * time.Second,
		)
		if availableAt.After(time.Now()) {
			continue
		}

		for _, excluded := range exclude {
			if utxo.Txid == excluded.Txid && utxo.Vout == excluded.Vout {
				continue
			}
		}

		delayedUtxos = append(delayedUtxos, utxo)
		selectedAmount += utxo.Amount
	}

	if selectedAmount < targetAmount {
		return nil, nil, 0, fmt.Errorf(
			"not enough funds to cover amount %d", targetAmount,
		)
	}

	return utxos, delayedUtxos, selectedAmount - targetAmount, nil
}

func (a *arkClient) ping(
	ctx context.Context, req *arkv1.PingRequest,
) func() {
	_, err := a.client.Ping(ctx, req)
	if err != nil {
		return nil
	}

	ticker := time.NewTicker(5 * time.Second)

	go func(t *time.Ticker) {
		for range t.C {
			// nolint
			a.client.Ping(ctx, req)
		}
	}(ticker)

	return ticker.Stop
}

func (a *arkClient) GetWalletStore(
	ctx context.Context, password string,
) (walletstore.WalletStore, error) {
	if _, err := a.wallet.Unlock(ctx, password); err != nil {
		return nil, err
	}

	return a.wallet.GetStore(ctx)
}
