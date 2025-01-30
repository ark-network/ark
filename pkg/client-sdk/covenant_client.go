package arksdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/redemption"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
)

type liquidReceiver struct {
	to     string
	amount uint64
}

func NewLiquidReceiver(to string, amount uint64) Receiver {
	return liquidReceiver{to, amount}
}

func (r liquidReceiver) To() string {
	return r.to
}

func (r liquidReceiver) Amount() uint64 {
	return r.amount
}

func (r liquidReceiver) IsOnchain() bool {
	_, err := address.ToOutputScript(r.to)
	return err == nil
}

type covenantArkClient struct {
	*arkClient
}

func NewCovenantClient(sdkStore types.Store) (ArkClient, error) {
	cfgData, err := sdkStore.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}

	if cfgData != nil {
		return nil, ErrAlreadyInitialized
	}

	return &covenantArkClient{
		&arkClient{
			store: sdkStore,
		},
	}, nil
}

func LoadCovenantClient(sdkStore types.Store) (ArkClient, error) {
	if sdkStore == nil {
		return nil, fmt.Errorf("missin sdk repository")
	}

	cfgData, err := sdkStore.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}

	if cfgData == nil {
		return nil, ErrNotInitialized
	}

	clientSvc, err := getClient(
		supportedClients, cfgData.ClientType, cfgData.ServerUrl,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup transport client: %s", err)
	}

	explorerSvc, err := getExplorer(cfgData.ExplorerURL, cfgData.Network.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to setup explorer: %s", err)
	}

	walletSvc, err := getWallet(
		sdkStore.ConfigStore(),
		cfgData,
		supportedWallets,
	)
	if err != nil {
		return nil, fmt.Errorf("faile to setup wallet: %s", err)
	}

	covenantClient := covenantArkClient{
		&arkClient{
			Config:   cfgData,
			wallet:   walletSvc,
			store:    sdkStore,
			explorer: explorerSvc,
			client:   clientSvc,
		},
	}

	if cfgData.WithTransactionFeed {
		txStreamCtx, txStreamCtxCancel := context.WithCancel(context.Background())
		covenantClient.txStreamCtxCancel = txStreamCtxCancel
		go covenantClient.listenForTxStream(txStreamCtx)
		go covenantClient.listenForBoardingUtxos(txStreamCtx)
	}

	return &covenantClient, nil
}

func LoadCovenantClientWithWallet(
	sdkStore types.Store, walletSvc wallet.WalletService,
) (ArkClient, error) {
	if sdkStore == nil {
		return nil, fmt.Errorf("missin sdk repository")
	}

	if walletSvc == nil {
		return nil, fmt.Errorf("missin wallet service")
	}

	cfgData, err := sdkStore.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}
	if cfgData == nil {
		return nil, ErrNotInitialized
	}

	clientSvc, err := getClient(
		supportedClients, cfgData.ClientType, cfgData.ServerUrl,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup transport client: %s", err)
	}

	explorerSvc, err := getExplorer(cfgData.ExplorerURL, cfgData.Network.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to setup explorer: %s", err)
	}

	covenantClient := covenantArkClient{
		&arkClient{
			Config:   cfgData,
			wallet:   walletSvc,
			store:    sdkStore,
			explorer: explorerSvc,
			client:   clientSvc,
		},
	}

	if cfgData.WithTransactionFeed {
		txStreamCtx, txStreamCtxCancel := context.WithCancel(context.Background())
		covenantClient.txStreamCtxCancel = txStreamCtxCancel
		go covenantClient.listenForTxStream(txStreamCtx)
		go covenantClient.listenForBoardingUtxos(txStreamCtx)
	}

	return &covenantClient, nil
}

func (a *covenantArkClient) Init(ctx context.Context, args InitArgs) error {
	err := a.arkClient.init(ctx, args)
	if err != nil {
		return err
	}

	if args.WithTransactionFeed {
		txStreamCtx, txStreamCtxCancel := context.WithCancel(context.Background())
		a.txStreamCtxCancel = txStreamCtxCancel
		go a.listenForTxStream(txStreamCtx)
		go a.listenForBoardingUtxos(txStreamCtx)
	}

	return nil
}

func (a *covenantArkClient) InitWithWallet(ctx context.Context, args InitWithWalletArgs) error {
	err := a.arkClient.initWithWallet(ctx, args)
	if err != nil {
		return err
	}

	if a.WithTransactionFeed {
		txStreamCtx, txStreamCtxCancel := context.WithCancel(context.Background())
		a.txStreamCtxCancel = txStreamCtxCancel
		go a.listenForTxStream(txStreamCtx)
		go a.listenForBoardingUtxos(txStreamCtx)
	}

	return nil
}

func (a *covenantArkClient) RedeemNotes(_ context.Context, _ []string, _ ...Option) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (a *covenantArkClient) SetNostrNotificationRecipient(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (a *covenantArkClient) listenForTxStream(ctx context.Context) {
	eventChan, closeFunc, err := a.client.GetTransactionsStream(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to get transaction stream")
		return
	}
	defer closeFunc()

	for {
		select {
		case event, ok := <-eventChan:
			if !ok {
				return
			}

			a.processTransactionEvent(event)
		case <-ctx.Done():
			return
		}
	}
}

func (a *covenantArkClient) processTransactionEvent(
	event client.TransactionEvent,
) {
	// TODO: considering current covenant state where all transactions happening in round
	// and that this is going to change we leave this unimplemented for now.
	// Also, with current state it is not possible to cover some edge cases like when in a round there
	// are multiple boarding inputs + spent vtxo with change in spendable + received in the same round
}

func (a *covenantArkClient) listenForBoardingUtxos(
	ctx context.Context,
) {
	// TODO considering current covenant state where all transactions happening in round
	// and that this is going to change we leave this unimplemented for now.
	// Also, with current state it is not possible to cover some edge cases like when in a round there
	// are multiple boarding inputs + spent vtxo with change in spendable + received in the same round
}

func (a *covenantArkClient) Balance(
	ctx context.Context, computeVtxoExpiration bool,
) (*Balance, error) {
	offchainAddrs, boardingAddrs, redeemAddrs, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	const nbWorkers = 3
	wg := &sync.WaitGroup{}
	wg.Add(nbWorkers * len(offchainAddrs))

	chRes := make(chan balanceRes, nbWorkers*len(offchainAddrs))
	for i := range offchainAddrs {
		boardingAddr := boardingAddrs[i]
		redeemAddr := redeemAddrs[i]

		go func() {
			defer wg.Done()
			balance, amountByExpiration, err := a.getOffchainBalance(
				ctx, computeVtxoExpiration,
			)
			if err != nil {
				chRes <- balanceRes{err: err}
				return
			}

			chRes <- balanceRes{
				offchainBalance:             balance,
				offchainBalanceByExpiration: amountByExpiration,
			}
		}()

		getDelayedBalance := func(addr string) {
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
		}

		go getDelayedBalance(boardingAddr.Address)
		go getDelayedBalance(redeemAddr.Address)
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
		if count == nbWorkers {
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

func (a *covenantArkClient) SendOnChain(
	ctx context.Context, receivers []Receiver,
) (string, error) {
	for _, receiver := range receivers {
		if !receiver.IsOnchain() {
			return "", fmt.Errorf("invalid receiver address '%s': must be onchain", receiver.To())
		}
	}

	return a.sendOnchain(ctx, receivers)
}

func (a *covenantArkClient) SendOffChain(
	ctx context.Context,
	withExpiryCoinselect bool, receivers []Receiver,
	_ bool,
) (string, error) {
	for _, receiver := range receivers {
		if receiver.IsOnchain() {
			return "", fmt.Errorf("invalid receiver address '%s': must be offchain", receiver.To())
		}
	}

	return a.sendOffchain(ctx, withExpiryCoinselect, receivers)
}

func (a *covenantArkClient) UnilateralRedeem(ctx context.Context) error {
	if a.wallet.IsLocked() {
		return fmt.Errorf("wallet is locked")
	}

	vtxos, err := a.getVtxos(ctx, false, nil)
	if err != nil {
		return err
	}

	totalVtxosAmount := uint64(0)
	for _, vtxo := range vtxos {
		totalVtxosAmount += vtxo.Amount
	}

	// transactionsMap avoid duplicates
	transactionsMap := make(map[string]struct{}, 0)
	transactions := make([]string, 0)

	redeemBranches, err := a.getRedeemBranches(ctx, vtxos)
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

func (a *covenantArkClient) CollaborativeRedeem(
	ctx context.Context,
	addr string, amount uint64, withExpiryCoinselect bool,
	opts ...Option,
) (string, error) {
	if a.wallet.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

	// validate liquid address
	if _, err := address.ToOutputScript(addr); err != nil {
		return "", fmt.Errorf("invalid onchain address")
	}

	if isConf, err := address.IsConfidential(addr); err != nil || isConf {
		return "", fmt.Errorf("confidential onchain address not supported")
	}

	offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}

	receivers := []client.Output{
		{
			Address: addr,
			Amount:  amount,
		},
	}

	vtxos := make([]client.TapscriptsVtxo, 0)
	spendableVtxos, err := a.getVtxos(ctx, false, nil)
	if err != nil {
		return "", err
	}

	for _, offchainAddr := range offchainAddrs {
		for _, v := range spendableVtxos {
			vtxoAddr, err := v.Address(a.ServerPubKey, a.Network)
			if err != nil {
				return "", err
			}

			if vtxoAddr == offchainAddr.Address {
				vtxos = append(vtxos, client.TapscriptsVtxo{
					Vtxo:       v,
					Tapscripts: offchainAddr.Tapscripts,
				})
			}
		}
	}

	boardingUtxos, err := a.getClaimableBoardingUtxos(ctx, nil)
	if err != nil {
		return "", err
	}

	selectedBoardingUtxos, selectedCoins, changeAmount, err := utils.CoinSelect(
		boardingUtxos, vtxos, amount, a.Dust, withExpiryCoinselect,
	)
	if err != nil {
		return "", err
	}

	if changeAmount > 0 {
		offchainAddr, _, err := a.wallet.NewAddress(ctx, true)
		if err != nil {
			return "", err
		}

		receivers = append(receivers, client.Output{
			Address: offchainAddr.Address,
			Amount:  changeAmount,
		})
	}

	inputs := make([]client.Input, 0, len(selectedCoins)+len(selectedBoardingUtxos))

	for _, coin := range selectedCoins {
		inputs = append(inputs, client.Input{
			Outpoint: client.Outpoint{
				Txid: coin.Txid,
				VOut: coin.VOut,
			},
			Tapscripts: coin.Tapscripts,
		})
	}
	for _, coin := range selectedBoardingUtxos {
		inputs = append(inputs, client.Input{
			Outpoint: client.Outpoint{
				Txid: coin.Txid,
				VOut: coin.VOut,
			},
			Tapscripts: coin.Tapscripts,
		})
	}

	requestID, err := a.client.RegisterInputsForNextRound(ctx, inputs)
	if err != nil {
		return "", err
	}

	if err := a.client.RegisterOutputsForNextRound(ctx, requestID, receivers, nil); err != nil {
		return "", err
	}

	roundTxID, err := a.handleRoundStream(ctx, requestID, selectedCoins, selectedBoardingUtxos, receivers)
	if err != nil {
		return "", err
	}

	return roundTxID, nil
}

func (a *covenantArkClient) Settle(
	ctx context.Context,
	_ ...Option, // no options for covenant
) (string, error) {
	return a.sendOffchain(ctx, false, nil)
}

func (a *covenantArkClient) GetTransactionHistory(
	ctx context.Context,
) ([]types.Transaction, error) {
	if a.Config.WithTransactionFeed {
		return a.store.TransactionStore().GetAllTransactions(ctx)
	}

	spendableVtxos, spentVtxos, err := a.ListVtxos(ctx)
	if err != nil {
		return nil, err
	}

	config, err := a.store.ConfigStore().GetData(ctx)
	if err != nil {
		return nil, err
	}

	boardingTxs := a.getBoardingTxs(ctx)

	return vtxosToTxsCovenant(config.VtxoTreeExpiry, spendableVtxos, spentVtxos, boardingTxs)
}

func (a *covenantArkClient) getAllBoardingUtxos(ctx context.Context) ([]types.Utxo, error) {
	_, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	utxos := make([]types.Utxo, 0)
	for _, addr := range boardingAddrs {
		txs, err := a.explorer.GetTxs(addr.Address)
		if err != nil {
			continue
		}
		for _, tx := range txs {
			for i, vout := range tx.Vout {
				if vout.Address == addr.Address {
					createdAt := time.Time{}
					if tx.Status.Confirmed {
						createdAt = time.Unix(tx.Status.Blocktime, 0)
					}
					utxos = append(utxos, types.Utxo{
						Txid:       tx.Txid,
						VOut:       uint32(i),
						Amount:     vout.Amount,
						CreatedAt:  createdAt,
						Tapscripts: addr.Tapscripts,
					})
				}
			}
		}
	}

	return utxos, nil
}

func (a *covenantArkClient) getClaimableBoardingUtxos(ctx context.Context, opts *CoinSelectOptions) ([]types.Utxo, error) {
	_, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	claimable := make([]types.Utxo, 0)

	for _, addr := range boardingAddrs {
		boardingScript, err := tree.ParseVtxoScript(addr.Tapscripts)
		if err != nil {
			return nil, err
		}

		boardingTimeout, err := boardingScript.SmallestExitDelay()
		if err != nil {
			return nil, err
		}

		boardingUtxos, err := a.explorer.GetUtxos(addr.Address)
		if err != nil {
			return nil, err
		}

		now := time.Now()

		for _, utxo := range boardingUtxos {
			if opts != nil && len(opts.OutpointsFilter) > 0 {
				utxoOutpoint := client.Outpoint{
					Txid: utxo.Txid,
					VOut: utxo.Vout,
				}
				found := false
				for _, outpoint := range opts.OutpointsFilter {
					if outpoint.Equals(utxoOutpoint) {
						found = true
						break
					}
				}

				if !found {
					continue
				}
			}

			u := utxo.ToUtxo(*boardingTimeout, addr.Tapscripts)
			if u.SpendableAt.Before(now) {
				continue
			}
			claimable = append(claimable, u)
		}
	}

	return claimable, nil
}

func (a *covenantArkClient) sendOnchain(
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

	net := utils.ToElementsNetwork(a.Network)

	targetAmount := uint64(0)
	for _, receiver := range receivers {
		if receiver.Amount() < a.Dust {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount(), a.Dust)
		}
		targetAmount += receiver.Amount()

		script, err := address.ToOutputScript(receiver.To())
		if err != nil {
			return "", err
		}

		if err := updater.AddOutputs([]psetv2.OutputArgs{
			{
				Asset:  net.AssetID,
				Amount: receiver.Amount(),
				Script: script,
			},
		}); err != nil {
			return "", err
		}
	}

	utxos, change, err := a.coinSelectOnchain(
		ctx, targetAmount, nil,
	)
	if err != nil {
		return "", err
	}

	if err := a.addInputs(ctx, updater, utxos); err != nil {
		return "", err
	}

	if change > 0 {
		_, changeAddr, err := a.wallet.NewAddress(ctx, true)
		if err != nil {
			return "", err
		}

		changeScript, err := address.ToOutputScript(changeAddr.Address)
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
		selected, newChange, err := a.coinSelectOnchain(
			ctx, feeAmount-change, utxos,
		)
		if err != nil {
			return "", err
		}

		if err := a.addInputs(ctx, updater, selected); err != nil {
			return "", err
		}

		if newChange > 0 {
			_, changeAddr, err := a.wallet.NewAddress(ctx, true)
			if err != nil {
				return "", err
			}

			changeScript, err := address.ToOutputScript(changeAddr.Address)
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

func (a *covenantArkClient) sendOffchain(
	ctx context.Context,
	withExpiryCoinselect bool, receivers []Receiver,
) (string, error) {
	if a.wallet.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

	expectedServerPubkey := schnorr.SerializePubKey(a.ServerPubKey)
	outputs := make([]client.Output, 0)
	sumOfReceivers := uint64(0)

	// validate receivers and create outputs
	for _, receiver := range receivers {
		rcvAddr, err := common.DecodeAddress(receiver.To())
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		rcvServerPubKkey := schnorr.SerializePubKey(rcvAddr.Server)

		if !bytes.Equal(expectedServerPubkey, rcvServerPubKkey) {
			return "", fmt.Errorf("invalid receiver address '%s': expected server %s, got %s", receiver.To(), hex.EncodeToString(expectedServerPubkey), hex.EncodeToString(rcvServerPubKkey))
		}

		if receiver.Amount() < a.Dust {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount(), a.Dust)
		}

		outputs = append(outputs, client.Output{
			Address: receiver.To(),
			Amount:  receiver.Amount(),
		})
		sumOfReceivers += receiver.Amount()
	}

	offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}
	if len(offchainAddrs) <= 0 {
		return "", fmt.Errorf("no offchain addresses found")
	}

	vtxos := make([]client.TapscriptsVtxo, 0)

	spendableVtxos, err := a.getVtxos(ctx, withExpiryCoinselect, nil)
	if err != nil {
		return "", err
	}

	for _, offchainAddr := range offchainAddrs {
		for _, v := range spendableVtxos {
			vtxoAddr, err := v.Address(a.ServerPubKey, a.Network)
			if err != nil {
				return "", err
			}

			if vtxoAddr == offchainAddr.Address {
				vtxos = append(vtxos, client.TapscriptsVtxo{
					Vtxo:       v,
					Tapscripts: offchainAddr.Tapscripts,
				})
			}
		}
	}

	boardingUtxos, err := a.getClaimableBoardingUtxos(ctx, nil)
	if err != nil {
		return "", err
	}

	var selectedBoardingCoins []types.Utxo
	var selectedCoins []client.TapscriptsVtxo
	var changeAmount uint64

	// if no receivers, self send all selected coins
	if len(outputs) <= 0 {
		selectedBoardingCoins = boardingUtxos
		selectedCoins = vtxos

		amount := uint64(0)
		for _, utxo := range boardingUtxos {
			amount += utxo.Amount
		}
		for _, utxo := range vtxos {
			amount += utxo.Amount
		}

		outputs = append(outputs, client.Output{
			Address: offchainAddrs[0].Address,
			Amount:  amount,
		})

		changeAmount = 0
	} else {
		selectedBoardingCoins, selectedCoins, changeAmount, err = utils.CoinSelect(
			boardingUtxos, vtxos, sumOfReceivers, a.Dust, withExpiryCoinselect,
		)
		if err != nil {
			return "", err
		}
	}

	if changeAmount > 0 {
		offchainAddr, _, err := a.wallet.NewAddress(ctx, true)
		if err != nil {
			return "", err
		}

		outputs = append(outputs, client.Output{
			Address: offchainAddr.Address,
			Amount:  changeAmount,
		})
	}

	inputs := make([]client.Input, 0, len(selectedCoins)+len(selectedBoardingCoins))

	for _, coin := range selectedCoins {
		inputs = append(inputs, client.Input{
			Outpoint: client.Outpoint{
				Txid: coin.Txid,
				VOut: coin.VOut,
			},
			Tapscripts: coin.Tapscripts,
		})
	}
	for _, coin := range selectedBoardingCoins {
		inputs = append(inputs, client.Input{
			Outpoint: client.Outpoint{
				Txid: coin.Txid,
				VOut: coin.VOut,
			},
			Tapscripts: coin.Tapscripts,
		})
	}

	requestID, err := a.client.RegisterInputsForNextRound(ctx, inputs)
	if err != nil {
		return "", err
	}

	if err := a.client.RegisterOutputsForNextRound(
		ctx, requestID, outputs, nil,
	); err != nil {
		return "", err
	}

	log.Infof("payout registered with id: %s", requestID)

	roundTxID, err := a.handleRoundStream(
		ctx, requestID, selectedCoins, boardingUtxos, outputs,
	)
	if err != nil {
		return "", err
	}

	return roundTxID, nil
}

// addInputs adds the inputs to the pset for send onchain
func (a *covenantArkClient) addInputs(
	ctx context.Context,
	updater *psetv2.Updater,
	utxos []types.Utxo,
) error {
	// TODO works only with single-key wallet
	offchain, _, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return err
	}

	vtxoScript, err := tree.ParseVtxoScript(offchain.Tapscripts)
	if err != nil {
		return err
	}

	forfeitClosure := vtxoScript.ForfeitClosures()[0]

	forfeitScript, err := forfeitClosure.Script()
	if err != nil {
		return err
	}

	forfeitLeaf := taproot.NewBaseTapElementsLeaf(forfeitScript)

	_, taprootTree, err := vtxoScript.TapTree()
	if err != nil {
		return err
	}

	leafProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
	if err != nil {
		return err
	}

	controlBlock, err := taproot.ParseControlBlock(leafProof.Script)
	if err != nil {
		return err
	}

	for _, utxo := range utxos {
		sequence, err := utxo.Sequence()
		if err != nil {
			return err
		}

		if err := updater.AddInputs([]psetv2.InputArgs{
			{
				Txid:     utxo.Txid,
				TxIndex:  utxo.VOut,
				Sequence: sequence,
			},
		}); err != nil {
			return err
		}

		inputIndex := len(updater.Pset.Inputs) - 1

		if err := updater.AddInTapLeafScript(
			inputIndex,
			psetv2.TapLeafScript{
				TapElementsLeaf: taproot.NewBaseTapElementsLeaf(leafProof.Script),
				ControlBlock:    *controlBlock,
			},
		); err != nil {
			return err
		}
	}

	return nil
}

func (a *covenantArkClient) handleRoundStream(
	ctx context.Context,
	requestID string,
	vtxosToSign []client.TapscriptsVtxo,
	boardingUtxos []types.Utxo,
	receivers []client.Output,
) (string, error) {
	eventsCh, close, err := a.client.GetEventStream(ctx, requestID)
	if err != nil {
		return "", err
	}

	var pingStop func()
	for pingStop == nil {
		pingStop = a.ping(ctx, requestID)
	}

	defer func() {
		pingStop()
		close()
	}()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case notify := <-eventsCh:
			if notify.Err != nil {
				return "", err
			}

			switch event := notify.Event; event.(type) {
			case client.RoundFinalizedEvent:
				return event.(client.RoundFinalizedEvent).Txid, nil
			case client.RoundFailedEvent:
				return "", fmt.Errorf("round failed: %s", event.(client.RoundFailedEvent).Reason)
			case client.RoundFinalizationEvent:
				pingStop()
				log.Info("a round finalization started")

				signedForfeitTxs, signedRoundTx, err := a.handleRoundFinalization(
					ctx, event.(client.RoundFinalizationEvent), vtxosToSign, boardingUtxos, receivers,
				)
				if err != nil {
					return "", err
				}

				if len(signedForfeitTxs) <= 0 && len(vtxosToSign) > 0 {
					log.Info("no forfeit txs to sign, waiting for the next round")
					continue
				}

				log.Info("submitting forfeit transactions... ")
				if err := a.client.SubmitSignedForfeitTxs(ctx, signedForfeitTxs, signedRoundTx); err != nil {
					return "", err
				}

				log.Info("done.")
				log.Info("waiting for round finalization...")
			}
		}
	}
}

func (a *covenantArkClient) handleRoundFinalization(
	ctx context.Context,
	event client.RoundFinalizationEvent,
	vtxos []client.TapscriptsVtxo,
	boardingUtxos []types.Utxo,
	receivers []client.Output,
) (signedForfeits []string, signedRoundTx string, err error) {
	if err = a.validateVtxoTree(event, receivers); err != nil {
		return
	}

	if len(vtxos) > 0 {
		signedForfeits, err = a.createAndSignForfeits(ctx, vtxos, event.Connectors, event.MinRelayFeeRate)
		if err != nil {
			return
		}
	}

	// if no boarding utxos inputs, we don't need to sign the round transaction
	if len(boardingUtxos) <= 0 {
		return
	}

	roundPtx, err := psetv2.NewPsetFromBase64(event.Tx)
	if err != nil {
		return nil, "", err
	}

	updater, err := psetv2.NewUpdater(roundPtx)
	if err != nil {
		return nil, "", err
	}

	for _, boardingUtxo := range boardingUtxos {
		boardingVtxoScript, err := tree.ParseVtxoScript(boardingUtxo.Tapscripts)
		if err != nil {
			return nil, "", err
		}

		forfeitClosure := boardingVtxoScript.ForfeitClosures()[0]

		forfeitScript, err := forfeitClosure.Script()
		if err != nil {
			return nil, "", err
		}

		forfeitLeaf := taproot.NewBaseTapElementsLeaf(forfeitScript)

		_, taprootTree, err := boardingVtxoScript.TapTree()
		if err != nil {
			return nil, "", err
		}

		forfeitProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
		if err != nil {
			return nil, "", err
		}

		ctrlBlock, err := taproot.ParseControlBlock(forfeitProof.ControlBlock)
		if err != nil {
			return nil, "", err
		}

		tapscript := psetv2.TapLeafScript{
			TapElementsLeaf: taproot.NewBaseTapElementsLeaf(forfeitProof.Script),
			ControlBlock:    *ctrlBlock,
		}

		for i, input := range updater.Pset.Inputs {
			if chainhash.Hash(input.PreviousTxid).String() == boardingUtxo.Txid && boardingUtxo.VOut == input.PreviousTxIndex {
				if err := updater.AddInTapLeafScript(i, tapscript); err != nil {
					return nil, "", err
				}
				break
			}
		}

	}

	b64, err := updater.Pset.ToBase64()
	if err != nil {
		return nil, "", err
	}

	signedRoundTx, err = a.wallet.SignTransaction(ctx, a.explorer, b64)
	if err != nil {
		return nil, "", err
	}

	return signedForfeits, signedRoundTx, nil
}

func (a *covenantArkClient) validateVtxoTree(
	event client.RoundFinalizationEvent, receivers []client.Output,
) error {
	roundTx := event.Tx
	ptx, err := psetv2.NewPsetFromBase64(roundTx)
	if err != nil {
		return err
	}

	connectors := event.Connectors

	if !utils.IsOnchainOnly(receivers) {
		if err := tree.ValidateVtxoTree(
			event.Tree, roundTx, a.Config.ServerPubKey, a.VtxoTreeExpiry,
		); err != nil {
			return err
		}
	}

	if err := common.ValidateConnectors(roundTx, connectors); err != nil {
		return err
	}

	if err := a.validateReceivers(
		ptx, receivers, event.Tree,
	); err != nil {
		return err
	}

	return nil
}

func (a *covenantArkClient) validateReceivers(
	ptx *psetv2.Pset,
	receivers []client.Output,
	vtxoTree tree.VtxoTree,
) error {
	for _, receiver := range receivers {
		isOnChain, onchainScript, err := utils.ParseLiquidAddress(
			receiver.Address,
		)
		if err != nil {
			return fmt.Errorf("invalid receiver address: %s err = %s", receiver.Address, err)
		}

		if isOnChain {
			if err := a.validateOnChainReceiver(ptx, receiver, onchainScript); err != nil {
				return err
			}
		} else {
			if err := a.validateOffChainReceiver(
				vtxoTree, receiver,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *covenantArkClient) validateOnChainReceiver(
	ptx *psetv2.Pset,
	receiver client.Output,
	onchainScript []byte,
) error {
	found := false
	for _, output := range ptx.Outputs {
		if bytes.Equal(output.Script, onchainScript) {
			if output.Value != receiver.Amount {
				return fmt.Errorf(
					"invalid collaborative exit output amount: got %d, want %d",
					output.Value, receiver.Amount,
				)
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("collaborative exit output not found: %s", receiver.Address)
	}
	return nil
}

func (a *covenantArkClient) validateOffChainReceiver(
	vtxoTree tree.VtxoTree,
	receiver client.Output,
) error {
	found := false

	addr, err := common.DecodeAddress(receiver.Address)
	if err != nil {
		return err
	}

	vtxoTapKey := schnorr.SerializePubKey(addr.VtxoTapKey)

	leaves := vtxoTree.Leaves()
	for _, leaf := range leaves {
		tx, err := psetv2.NewPsetFromBase64(leaf.Tx)
		if err != nil {
			return err
		}

		for _, output := range tx.Outputs {
			if len(output.Script) == 0 {
				continue
			}
			if bytes.Equal(output.Script[2:], vtxoTapKey) {
				if output.Value == receiver.Amount {
					found = true
					break
				}
			}
		}

		if found {
			break
		}
	}

	if !found {
		return fmt.Errorf("off-chain send output not found: %s", receiver.Address)
	}
	return nil
}

func (a *covenantArkClient) createAndSignForfeits(
	ctx context.Context,
	vtxosToSign []client.TapscriptsVtxo,
	connectors []string,
	feeRate chainfee.SatPerKVByte,
) ([]string, error) {
	signedForfeits := make([]string, 0)
	connectorsPsets := make([]*psetv2.Pset, 0, len(connectors))

	forfeitPkScript, err := address.ToOutputScript(a.ForfeitAddress)
	if err != nil {
		return nil, err
	}

	for _, connector := range connectors {
		p, err := psetv2.NewPsetFromBase64(connector)
		if err != nil {
			return nil, err
		}

		connectorsPsets = append(connectorsPsets, p)
	}

	for _, vtxo := range vtxosToSign {
		vtxoScript, err := tree.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return nil, err
		}

		vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
		if err != nil {
			return nil, err
		}

		vtxoOutputScript, err := common.P2TRScript(vtxoTapKey)
		if err != nil {
			return nil, err
		}

		vtxoInput := psetv2.InputArgs{
			Txid:    vtxo.Txid,
			TxIndex: vtxo.VOut,
		}

		forfeitClosure := vtxoScript.ForfeitClosures()[0]

		forfeitScript, err := forfeitClosure.Script()
		if err != nil {
			return nil, err
		}

		forfeitLeaf := taproot.NewBaseTapElementsLeaf(forfeitScript)

		leafProof, err := vtxoTapTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
		if err != nil {
			return nil, err
		}

		ctrlBlock, err := taproot.ParseControlBlock(leafProof.ControlBlock)
		if err != nil {
			return nil, err
		}

		tapscript := psetv2.TapLeafScript{
			TapElementsLeaf: taproot.NewBaseTapElementsLeaf(leafProof.Script),
			ControlBlock:    *ctrlBlock,
		}

		feeAmount, err := common.ComputeForfeitTxFee(
			feeRate,
			&waddrmgr.Tapscript{
				RevealedScript: leafProof.Script,
				ControlBlock:   &ctrlBlock.ControlBlock,
			},
			forfeitClosure.WitnessSize(),
			txscript.WitnessV0PubKeyHashTy,
		)
		if err != nil {
			return nil, err
		}

		if cltv, ok := forfeitClosure.(*tree.CLTVMultisigClosure); ok {
			vtxoInput.TimeLock = uint32(cltv.Locktime)
			vtxoInput.Sequence = wire.MaxTxInSequenceNum - 1
		}

		for _, connectorPset := range connectorsPsets {
			forfeits, err := tree.BuildForfeitTxs(
				connectorPset, vtxoInput, vtxo.Amount, a.Dust, feeAmount, vtxoOutputScript, forfeitPkScript,
			)
			if err != nil {
				return nil, err
			}

			for _, forfeit := range forfeits {
				updater, err := psetv2.NewUpdater(forfeit)
				if err != nil {
					return nil, err
				}

				if err := updater.AddInTapLeafScript(1, tapscript); err != nil {
					return nil, err
				}

				b64, err := updater.Pset.ToBase64()
				if err != nil {
					return nil, err
				}

				signedForfeit, err := a.wallet.SignTransaction(ctx, a.explorer, b64)
				if err != nil {
					return nil, err
				}

				signedForfeits = append(signedForfeits, signedForfeit)
			}
		}
	}

	return signedForfeits, nil
}

func (a *covenantArkClient) coinSelectOnchain(
	ctx context.Context, targetAmount uint64, exclude []types.Utxo,
) ([]types.Utxo, uint64, error) {
	_, boardingAddrs, redemptionAddrs, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, 0, err
	}

	now := time.Now()

	fetchedUtxos := make([]types.Utxo, 0)
	for _, addr := range boardingAddrs {
		boardingScript, err := tree.ParseVtxoScript(addr.Tapscripts)
		if err != nil {
			return nil, 0, err
		}

		boardingTimeout, err := boardingScript.SmallestExitDelay()
		if err != nil {
			return nil, 0, err
		}

		utxos, err := a.explorer.GetUtxos(addr.Address)
		if err != nil {
			return nil, 0, err
		}

		for _, utxo := range utxos {
			u := utxo.ToUtxo(*boardingTimeout, addr.Tapscripts)
			if u.SpendableAt.Before(now) {
				fetchedUtxos = append(fetchedUtxos, u)
			}
		}
	}

	selected := make([]types.Utxo, 0)
	selectedAmount := uint64(0)
	for _, utxo := range fetchedUtxos {
		if selectedAmount >= targetAmount {
			break
		}

		for _, excluded := range exclude {
			if utxo.Txid == excluded.Txid && utxo.VOut == excluded.VOut {
				continue
			}
		}

		selected = append(selected, utxo)
		selectedAmount += utxo.Amount
	}

	if selectedAmount >= targetAmount {
		return selected, selectedAmount - targetAmount, nil
	}

	fetchedUtxos = make([]types.Utxo, 0)
	for _, addr := range redemptionAddrs {
		utxos, err := a.explorer.GetUtxos(addr.Address)
		if err != nil {
			return nil, 0, err
		}

		for _, utxo := range utxos {
			u := utxo.ToUtxo(a.UnilateralExitDelay, addr.Tapscripts)
			if u.SpendableAt.Before(now) {
				fetchedUtxos = append(fetchedUtxos, u)
			}
		}
	}

	for _, utxo := range fetchedUtxos {
		if selectedAmount >= targetAmount {
			break
		}

		for _, excluded := range exclude {
			if utxo.Txid == excluded.Txid && utxo.VOut == excluded.VOut {
				continue
			}
		}

		selected = append(selected, utxo)
		selectedAmount += utxo.Amount
	}

	if selectedAmount < targetAmount {
		return nil, 0, fmt.Errorf(
			"not enough funds to cover amount %d", targetAmount,
		)
	}

	return selected, selectedAmount - targetAmount, nil
}

func (a *covenantArkClient) getRedeemBranches(
	ctx context.Context, vtxos []client.Vtxo,
) (map[string]*redemption.CovenantRedeemBranch, error) {
	vtxoTrees := make(map[string]tree.VtxoTree, 0)
	redeemBranches := make(map[string]*redemption.CovenantRedeemBranch, 0)

	for i := range vtxos {
		vtxo := vtxos[i]
		if _, ok := vtxoTrees[vtxo.RoundTxid]; !ok {
			round, err := a.client.GetRound(ctx, vtxo.RoundTxid)
			if err != nil {
				return nil, err
			}

			vtxoTrees[vtxo.RoundTxid] = round.Tree
		}

		redeemBranch, err := redemption.NewCovenantRedeemBranch(
			a.explorer, vtxoTrees[vtxo.RoundTxid], vtxo,
		)
		if err != nil {
			return nil, err
		}

		redeemBranches[vtxo.Txid] = redeemBranch
	}

	return redeemBranches, nil
}

func (a *covenantArkClient) getOffchainBalance(
	ctx context.Context, computeVtxoExpiration bool,
) (uint64, map[int64]uint64, error) {
	amountByExpiration := make(map[int64]uint64, 0)

	vtxos, err := a.getVtxos(ctx, computeVtxoExpiration, nil)
	if err != nil {
		return 0, nil, err
	}
	var balance uint64
	for _, vtxo := range vtxos {
		balance += vtxo.Amount

		if !vtxo.ExpiresAt.IsZero() {
			expiration := vtxo.ExpiresAt.Unix()

			if _, ok := amountByExpiration[expiration]; !ok {
				amountByExpiration[expiration] = 0
			}

			amountByExpiration[expiration] += vtxo.Amount
		}
	}

	return balance, amountByExpiration, nil
}

func (a *covenantArkClient) getVtxos(
	ctx context.Context,
	_ bool, opts *CoinSelectOptions,
) ([]client.Vtxo, error) {
	spendableVtxos, _, err := a.ListVtxos(ctx)
	if err != nil {
		return nil, err
	}

	if opts != nil && len(opts.OutpointsFilter) > 0 {
		spendableVtxos = filterByOutpoints(spendableVtxos, opts.OutpointsFilter)
	}

	if opts == nil || !opts.WithExpirySorting {
		return spendableVtxos, nil
	}

	// if sorting by expiry is required, we need to get the expiration date of each vtxo
	redeemBranches, err := a.getRedeemBranches(ctx, spendableVtxos)
	if err != nil {
		return nil, err
	}

	for vtxoTxid, branch := range redeemBranches {
		expiration, err := branch.ExpiresAt()
		if err != nil {
			return nil, err
		}

		for i, vtxo := range spendableVtxos {
			if vtxo.Txid == vtxoTxid {
				spendableVtxos[i].ExpiresAt = *expiration
				break
			}
		}
	}

	return spendableVtxos, nil
}

func (a *covenantArkClient) getBoardingTxs(ctx context.Context) (transactions []types.Transaction) {
	allUtxos, err := a.getAllBoardingUtxos(ctx)
	if err != nil {
		return nil
	}

	for _, u := range allUtxos {
		transactions = append(transactions, types.Transaction{
			TransactionKey: types.TransactionKey{
				BoardingTxid: u.Txid,
			},
			Amount:    u.Amount,
			Type:      types.TxReceived,
			CreatedAt: u.CreatedAt,
		})
	}
	return
}

func vtxosToTxsCovenant(
	vtxoTreeExpiry common.RelativeLocktime,
	spendable, spent []client.Vtxo,
	boardingTxs []types.Transaction,
) ([]types.Transaction, error) {
	transactions := make([]types.Transaction, 0)
	unconfirmedBoardingTxs := make([]types.Transaction, 0)
	for _, tx := range boardingTxs {
		emptyTime := time.Time{}
		if tx.CreatedAt == emptyTime {
			unconfirmedBoardingTxs = append(unconfirmedBoardingTxs, tx)
			continue
		}
		transactions = append(transactions, tx)
	}

	for _, v := range append(spendable, spent...) {
		// get vtxo amount
		amount := int(v.Amount)

		// find other spent vtxos that spent this one
		relatedVtxos := findVtxosBySpentBy(spent, v.Txid)
		for _, r := range relatedVtxos {
			if r.Amount < math.MaxInt64 {
				rAmount := int(r.Amount)
				amount -= rAmount
			}
		}
		// what kind of tx was this? send or receive?
		txType := types.TxReceived
		if amount < 0 {
			txType = types.TxSent
		}
		// get redeem txid
		redeemTxid := ""
		if len(v.RedeemTx) > 0 {
			txid, err := getRedeemTxidCovenant(v.RedeemTx)
			if err != nil {
				return nil, err
			}
			redeemTxid = txid
		}
		// add transaction
		transactions = append(transactions, types.Transaction{
			TransactionKey: types.TransactionKey{
				RoundTxid:  v.RoundTxid,
				RedeemTxid: redeemTxid,
			},
			Amount:    uint64(math.Abs(float64(amount))),
			Type:      txType,
			CreatedAt: getCreatedAtFromExpiry(vtxoTreeExpiry, v.ExpiresAt),
		})
	}

	// Sort the slice by age
	sort.Slice(transactions, func(i, j int) bool {
		txi := transactions[i]
		txj := transactions[j]
		if txi.CreatedAt.Equal(txj.CreatedAt) {
			return txi.Type > txj.Type
		}
		return txi.CreatedAt.After(txj.CreatedAt)
	})

	return append(unconfirmedBoardingTxs, transactions...), nil
}

func getRedeemTxidCovenant(redeemTx string) (string, error) {
	redeemPtx, err := psetv2.NewPsetFromBase64(redeemTx)
	if err != nil {
		return "", fmt.Errorf("failed to parse redeem tx: %s", err)
	}

	tx, err := redeemPtx.UnsignedTx()
	if err != nil {
		return "", fmt.Errorf("failed to get txid from redeem tx: %s", err)
	}

	return tx.TxHash().String(), nil
}
