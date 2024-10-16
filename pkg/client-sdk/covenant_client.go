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
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/redemption"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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
		supportedClients, cfgData.ClientType, cfgData.AspUrl,
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
		supportedClients, cfgData.ClientType, cfgData.AspUrl,
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

	if args.ListenTransactionStream {
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
	// TODO considering current covenant state where all payments happening in round
	//and that this is going to change we leave this unimplemented until asnc payments are implemented
	//also with current state it is not possible to cover some edge cases like when in a round there
	//are multiple boarding inputs + spent vtxo with change in spendable + received in the same round
}

func (a *covenantArkClient) listenForBoardingUtxos(
	ctx context.Context,
) {
	// TODO considering current covenant state where all payments happening in round
	//and that this is going to change we leave this unimplemented until asnc payments are implemented
	//also with current state it is not possible to cover some edge cases like when in a round there
	//are multiple boarding inputs + spent vtxo with change in spendable + received in the same round
}

func (a *covenantArkClient) ListVtxos(
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
		offchainAddr := offchainAddrs[i]
		boardingAddr := boardingAddrs[i]
		redeemAddr := redeemAddrs[i]

		go func(addr string) {
			defer wg.Done()
			balance, amountByExpiration, err := a.getOffchainBalance(
				ctx, addr, computeVtxoExpiration,
			)
			if err != nil {
				chRes <- balanceRes{err: err}
				return
			}

			chRes <- balanceRes{
				offchainBalance:             balance,
				offchainBalanceByExpiration: amountByExpiration,
			}
		}(offchainAddr.Address)

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

	offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return err
	}

	vtxos := make([]client.Vtxo, 0)
	for _, offchainAddr := range offchainAddrs {
		fetchedVtxos, _, err := a.client.ListVtxos(ctx, offchainAddr.Address)
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
	net := utils.ToElementsNetwork(a.Network)
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

	receivers := []client.Output{
		{
			Address: addr,
			Amount:  amount,
		},
	}

	vtxos := make([]client.DescriptorVtxo, 0)
	for _, offchainAddr := range offchainAddrs {
		spendableVtxos, err := a.getVtxos(ctx, offchainAddr.Address, withExpiryCoinselect)
		if err != nil {
			return "", err
		}

		for _, vtxo := range spendableVtxos {
			vtxos = append(vtxos, client.DescriptorVtxo{
				Vtxo:       vtxo,
				Descriptor: offchainAddr.Descriptor,
			})
		}
	}

	selectedCoins, changeAmount, err := utils.CoinSelect(
		vtxos, amount, a.Dust, withExpiryCoinselect,
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

	inputs := make([]client.Input, 0, len(selectedCoins))

	for _, coin := range selectedCoins {
		inputs = append(inputs, client.Input{
			Outpoint: client.Outpoint{
				Txid: coin.Txid,
				VOut: coin.VOut,
			},
			Descriptor: coin.Descriptor,
		})
	}

	paymentID, err := a.client.RegisterInputsForNextRound(ctx, inputs, "") // ephemeralPublicKey is not required for covenant
	if err != nil {
		return "", err
	}

	if err := a.client.RegisterOutputsForNextRound(ctx, paymentID, receivers); err != nil {
		return "", err
	}

	poolTxID, err := a.handleRoundStream(
		ctx, paymentID, selectedCoins, nil, "", receivers,
	)
	if err != nil {
		return "", err
	}

	return poolTxID, nil
}

func (a *covenantArkClient) SendAsync(
	ctx context.Context,
	withExpiryCoinselect bool, receivers []Receiver,
) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (a *covenantArkClient) Claim(ctx context.Context) (string, error) {
	myselfOffchain, boardingAddr, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", err
	}

	boardingUtxos, err := a.getClaimableBoardingUtxos(ctx)
	if err != nil {
		return "", err
	}

	var pendingBalance uint64
	for _, vtxo := range boardingUtxos {
		pendingBalance += vtxo.Amount
	}
	if pendingBalance == 0 {
		return "", fmt.Errorf("no funds to claim")
	}

	receiver := client.Output{
		Address: myselfOffchain.Address,
		Amount:  pendingBalance,
	}

	return a.selfTransferAllPendingPayments(
		ctx,
		boardingUtxos,
		receiver,
		boardingAddr.Descriptor,
	)
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

	return vtxosToTxsCovenant(config.RoundLifetime, spendableVtxos, spentVtxos, boardingTxs)
}

func (a *covenantArkClient) getAllBoardingUtxos(ctx context.Context) ([]explorer.Utxo, error) {
	_, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	utxos := []explorer.Utxo{}
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
					utxos = append(utxos, explorer.Utxo{
						Txid:      tx.Txid,
						Vout:      uint32(i),
						Amount:    vout.Amount,
						CreatedAt: createdAt,
					})
				}
			}
		}
	}

	return utxos, nil
}

func (a *covenantArkClient) getClaimableBoardingUtxos(ctx context.Context) ([]explorer.Utxo, error) {
	_, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	claimable := make([]explorer.Utxo, 0)

	for _, addr := range boardingAddrs {
		boardingScript, err := tree.ParseVtxoScript(addr.Descriptor)
		if err != nil {
			return nil, err
		}

		var boardingTimeout uint

		if defaultVtxo, ok := boardingScript.(*tree.DefaultVtxoScript); ok {
			boardingTimeout = defaultVtxo.ExitDelay
		} else {
			return nil, fmt.Errorf("unsupported boarding descriptor: %s", addr.Descriptor)
		}

		boardingUtxos, err := a.explorer.GetUtxos(addr.Address)
		if err != nil {
			return nil, err
		}

		now := time.Now()

		for _, utxo := range boardingUtxos {
			u := utxo.ToUtxo(boardingTimeout)

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

	expectedAspPubkey := schnorr.SerializePubKey(a.AspPubkey)

	receiversOutput := make([]client.Output, 0)
	sumOfReceivers := uint64(0)

	for _, receiver := range receivers {
		rcvAddr, err := common.DecodeAddress(receiver.To())
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		rcvAspPubkey := schnorr.SerializePubKey(rcvAddr.Asp)

		if !bytes.Equal(rcvAspPubkey, expectedAspPubkey) {
			return "", fmt.Errorf("invalid receiver address '%s': expected ASP %s, got %s", receiver.To(), hex.EncodeToString(expectedAspPubkey), hex.EncodeToString(rcvAspPubkey))
		}

		if receiver.Amount() < a.Dust {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount(), a.Dust)
		}

		receiversOutput = append(receiversOutput, client.Output{
			Address: receiver.To(),
			Amount:  receiver.Amount(),
		})
		sumOfReceivers += receiver.Amount()
	}

	vtxos := make([]client.DescriptorVtxo, 0)
	for _, offchainAddr := range offchainAddrs {
		spendableVtxos, err := a.getVtxos(ctx, offchainAddr.Address, withExpiryCoinselect)
		if err != nil {
			return "", err
		}

		for _, vtxo := range spendableVtxos {
			vtxos = append(vtxos, client.DescriptorVtxo{
				Vtxo:       vtxo,
				Descriptor: offchainAddr.Descriptor,
			})
		}
	}

	selectedCoins, changeAmount, err := utils.CoinSelect(
		vtxos, sumOfReceivers, a.Dust, withExpiryCoinselect,
	)
	if err != nil {
		return "", err
	}

	if changeAmount > 0 {
		offchainAddr, _, err := a.wallet.NewAddress(ctx, true)
		if err != nil {
			return "", err
		}

		changeReceiver := client.Output{
			Address: offchainAddr.Address,
			Amount:  changeAmount,
		}
		receiversOutput = append(receiversOutput, changeReceiver)
	}

	inputs := make([]client.Input, 0, len(selectedCoins))
	for _, coin := range selectedCoins {
		inputs = append(inputs, client.Input{
			Outpoint: client.Outpoint{
				Txid: coin.Txid,
				VOut: coin.VOut,
			},
			Descriptor: coin.Descriptor,
		})
	}

	paymentID, err := a.client.RegisterInputsForNextRound(
		ctx, inputs, "", // ephemeralPublicKey is not required for covenant
	)
	if err != nil {
		return "", err
	}

	if err := a.client.RegisterOutputsForNextRound(
		ctx, paymentID, receiversOutput,
	); err != nil {
		return "", err
	}

	log.Infof("payment registered with id: %s", paymentID)

	poolTxID, err := a.handleRoundStream(
		ctx, paymentID, selectedCoins, nil, "", receiversOutput,
	)
	if err != nil {
		return "", err
	}

	return poolTxID, nil
}

// addInputs adds the inputs to the pset for send onchain
func (a *covenantArkClient) addInputs(
	ctx context.Context,
	updater *psetv2.Updater,
	utxos []explorer.Utxo,
) error {
	// TODO works only with single-key wallet
	offchain, _, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return err
	}

	vtxoScript, err := tree.ParseVtxoScript(offchain.Descriptor)
	if err != nil {
		return err
	}

	var userPubkey, aspPubkey *secp256k1.PublicKey

	switch s := vtxoScript.(type) {
	case *tree.DefaultVtxoScript:
		userPubkey = s.Owner
		aspPubkey = s.Asp
	default:
		return fmt.Errorf("unsupported vtxo script: %T", s)
	}

	for _, utxo := range utxos {
		sequence, err := utxo.Sequence()
		if err != nil {
			return err
		}

		if err := updater.AddInputs([]psetv2.InputArgs{
			{
				Txid:     utxo.Txid,
				TxIndex:  utxo.Vout,
				Sequence: sequence,
			},
		}); err != nil {
			return err
		}

		vtxoScript := &tree.DefaultVtxoScript{
			Owner:     userPubkey,
			Asp:       aspPubkey,
			ExitDelay: utxo.Delay,
		}

		forfeitClosure := &tree.MultisigClosure{
			Pubkey:    userPubkey,
			AspPubkey: aspPubkey,
		}

		forfeitLeaf, err := forfeitClosure.Leaf()
		if err != nil {
			return err
		}

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
	paymentID string,
	vtxosToSign []client.DescriptorVtxo,
	boardingUtxos []explorer.Utxo,
	boardingDescriptor string,
	receivers []client.Output,
) (string, error) {
	eventsCh, close, err := a.client.GetEventStream(ctx, paymentID)
	if err != nil {
		return "", err
	}

	var pingStop func()
	for pingStop == nil {
		pingStop = a.ping(ctx, paymentID)
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
					ctx, event.(client.RoundFinalizationEvent), vtxosToSign, boardingUtxos, boardingDescriptor, receivers,
				)
				if err != nil {
					return "", err
				}

				if len(signedForfeitTxs) <= 0 && len(vtxosToSign) > 0 {
					log.Info("no forfeit txs to sign, waiting for the next round")
					continue
				}

				log.Info("finalizing payment... ")
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
	vtxos []client.DescriptorVtxo,
	boardingUtxos []explorer.Utxo,
	boardingDescriptor string,
	receivers []client.Output,
) (signedForfeits []string, signedRoundTx string, err error) {
	if err = a.validateCongestionTree(event, receivers); err != nil {
		return
	}

	if len(vtxos) > 0 {
		signedForfeits, err = a.createAndSignForfeits(ctx, vtxos, event.Connectors, event.MinRelayFeeRate)
		if err != nil {
			return
		}
	}

	if len(boardingUtxos) > 0 {
		boardingVtxoScript, err := tree.ParseVtxoScript(boardingDescriptor)
		if err != nil {
			return nil, "", err
		}

		roundPtx, err := psetv2.NewPsetFromBase64(event.Tx)
		if err != nil {
			return nil, "", err
		}

		var forfeitClosure tree.Closure

		switch s := boardingVtxoScript.(type) {
		case *tree.DefaultVtxoScript:
			forfeitClosure = &tree.MultisigClosure{
				Pubkey:    s.Owner,
				AspPubkey: a.AspPubkey,
			}
		default:
			return nil, "", fmt.Errorf("unsupported boarding descriptor: %s", boardingDescriptor)
		}

		forfeitLeaf, err := forfeitClosure.Leaf()
		if err != nil {
			return nil, "", err
		}

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

		updater, err := psetv2.NewUpdater(roundPtx)
		if err != nil {
			return nil, "", err
		}

		for i, input := range updater.Pset.Inputs {
			for _, boardingUtxo := range boardingUtxos {
				if chainhash.Hash(input.PreviousTxid).String() == boardingUtxo.Txid && boardingUtxo.Vout == input.PreviousTxIndex {
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
	}

	return signedForfeits, signedRoundTx, nil
}

func (a *covenantArkClient) validateCongestionTree(
	event client.RoundFinalizationEvent, receivers []client.Output,
) error {
	poolTx := event.Tx
	ptx, err := psetv2.NewPsetFromBase64(poolTx)
	if err != nil {
		return err
	}

	connectors := event.Connectors

	if !utils.IsOnchainOnly(receivers) {
		if err := tree.ValidateCongestionTree(
			event.Tree, poolTx, a.Config.AspPubkey, a.RoundLifetime,
		); err != nil {
			return err
		}
	}

	if err := common.ValidateConnectors(poolTx, connectors); err != nil {
		return err
	}

	if err := a.validateReceivers(
		ptx, receivers, event.Tree,
	); err != nil {
		return err
	}

	log.Infoln("congestion tree validated")

	return nil
}

func (a *covenantArkClient) validateReceivers(
	ptx *psetv2.Pset,
	receivers []client.Output,
	congestionTree tree.CongestionTree,
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
				congestionTree, receiver,
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
	congestionTree tree.CongestionTree,
	receiver client.Output,
) error {
	found := false

	addr, err := common.DecodeAddress(receiver.Address)
	if err != nil {
		return err
	}

	vtxoTapKey := schnorr.SerializePubKey(addr.VtxoTapKey)

	leaves := congestionTree.Leaves()
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
	vtxosToSign []client.DescriptorVtxo,
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
		vtxoScript, err := tree.ParseVtxoScript(vtxo.Descriptor)
		if err != nil {
			return nil, err
		}

		vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
		if err != nil {
			return nil, err
		}

		feeAmount, err := common.ComputeForfeitMinRelayFee(feeRate, vtxoTapTree, txscript.WitnessV0PubKeyHashTy)
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

		var forfeitClosure tree.Closure

		switch s := vtxoScript.(type) {
		case *tree.DefaultVtxoScript:
			forfeitClosure = &tree.MultisigClosure{
				Pubkey:    s.Owner,
				AspPubkey: a.AspPubkey,
			}
		default:
			return nil, fmt.Errorf("unsupported vtxo script: %T", s)
		}

		forfeitLeaf, err := forfeitClosure.Leaf()
		if err != nil {
			return nil, err
		}

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
	ctx context.Context, targetAmount uint64, exclude []explorer.Utxo,
) ([]explorer.Utxo, uint64, error) {
	_, boardingAddrs, redemptionAddrs, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, 0, err
	}

	now := time.Now()

	fetchedUtxos := make([]explorer.Utxo, 0)
	for _, addr := range boardingAddrs {
		boardingDescriptor := addr.Descriptor

		boardingScript, err := tree.ParseVtxoScript(boardingDescriptor)
		if err != nil {
			return nil, 0, err
		}

		var boardingTimeout uint

		if defaultVtxo, ok := boardingScript.(*tree.DefaultVtxoScript); ok {
			boardingTimeout = defaultVtxo.ExitDelay
		} else {
			return nil, 0, fmt.Errorf("unsupported boarding descriptor: %s", boardingDescriptor)
		}

		utxos, err := a.explorer.GetUtxos(addr.Address)
		if err != nil {
			return nil, 0, err
		}

		for _, utxo := range utxos {
			u := utxo.ToUtxo(boardingTimeout)
			if u.SpendableAt.Before(now) {
				fetchedUtxos = append(fetchedUtxos, u)
			}
		}
	}

	selected := make([]explorer.Utxo, 0)
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

		selected = append(selected, utxo)
		selectedAmount += utxo.Amount
	}

	if selectedAmount >= targetAmount {
		return selected, selectedAmount - targetAmount, nil
	}

	fetchedUtxos = make([]explorer.Utxo, 0)
	for _, addr := range redemptionAddrs {
		utxos, err := a.explorer.GetUtxos(addr.Address)
		if err != nil {
			return nil, 0, err
		}

		for _, utxo := range utxos {
			u := utxo.ToUtxo(uint(a.UnilateralExitDelay))
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
			if utxo.Txid == excluded.Txid && utxo.Vout == excluded.Vout {
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
	congestionTrees := make(map[string]tree.CongestionTree, 0)
	redeemBranches := make(map[string]*redemption.CovenantRedeemBranch, 0)

	for i := range vtxos {
		vtxo := vtxos[i]
		if _, ok := congestionTrees[vtxo.RoundTxid]; !ok {
			round, err := a.client.GetRound(ctx, vtxo.RoundTxid)
			if err != nil {
				return nil, err
			}

			congestionTrees[vtxo.RoundTxid] = round.Tree
		}

		redeemBranch, err := redemption.NewCovenantRedeemBranch(
			a.explorer, congestionTrees[vtxo.RoundTxid], vtxo,
		)
		if err != nil {
			return nil, err
		}

		redeemBranches[vtxo.Txid] = redeemBranch
	}

	return redeemBranches, nil
}

func (a *covenantArkClient) getOffchainBalance(
	ctx context.Context, addr string, computeVtxoExpiration bool,
) (uint64, map[int64]uint64, error) {
	amountByExpiration := make(map[int64]uint64, 0)

	vtxos, err := a.getVtxos(ctx, addr, computeVtxoExpiration)
	if err != nil {
		return 0, nil, err
	}
	var balance uint64
	for _, vtxo := range vtxos {
		balance += vtxo.Amount

		if vtxo.ExpiresAt != nil {
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
	ctx context.Context, addr string, computeVtxoExpiration bool,
) ([]client.Vtxo, error) {
	vtxos, _, err := a.client.ListVtxos(ctx, addr)
	if err != nil {
		return nil, err
	}

	if !computeVtxoExpiration {
		return vtxos, nil
	}

	redeemBranches, err := a.getRedeemBranches(ctx, vtxos)
	if err != nil {
		return nil, err
	}

	for vtxoTxid, branch := range redeemBranches {
		expiration, err := branch.ExpiresAt()
		if err != nil {
			return nil, err
		}

		for i, vtxo := range vtxos {
			if vtxo.Txid == vtxoTxid {
				vtxos[i].ExpiresAt = expiration
				break
			}
		}
	}

	return vtxos, nil
}

func (a *covenantArkClient) selfTransferAllPendingPayments(
	ctx context.Context, boardingUtxos []explorer.Utxo, myself client.Output, boardingDescriptor string,
) (string, error) {
	inputs := make([]client.Input, 0, len(boardingUtxos))

	for _, utxo := range boardingUtxos {
		inputs = append(inputs, client.Input{
			Outpoint: client.Outpoint{
				Txid: utxo.Txid,
				VOut: utxo.Vout,
			},
			Descriptor: boardingDescriptor,
		})
	}

	outputs := []client.Output{myself}

	paymentID, err := a.client.RegisterInputsForNextRound(ctx, inputs, "") // ephemeralPublicKey is not required for covenant
	if err != nil {
		return "", err
	}

	if err := a.client.RegisterOutputsForNextRound(ctx, paymentID, outputs); err != nil {
		return "", err
	}

	roundTxid, err := a.handleRoundStream(
		ctx, paymentID, make([]client.DescriptorVtxo, 0), boardingUtxos, boardingDescriptor, outputs,
	)
	if err != nil {
		return "", err
	}

	return roundTxid, nil
}

func (a *covenantArkClient) getBoardingTxs(ctx context.Context) (transactions []types.Transaction) {
	utxos, err := a.getClaimableBoardingUtxos(ctx)
	if err != nil {
		return nil
	}

	isPending := make(map[string]bool)
	for _, u := range utxos {
		isPending[u.Txid] = true
	}

	allUtxos, err := a.getAllBoardingUtxos(ctx)
	if err != nil {
		return nil
	}

	for _, u := range allUtxos {
		pending := false
		if isPending[u.Txid] {
			pending = true
		}

		transactions = append(transactions, types.Transaction{
			TransactionKey: types.TransactionKey{
				BoardingTxid: u.Txid,
			},
			Amount:    u.Amount,
			Type:      types.TxReceived,
			CreatedAt: u.CreatedAt,
			IsPending: pending,
		})
	}
	return
}

func vtxosToTxsCovenant(
	roundLifetime int64, spendable, spent []client.Vtxo, boardingTxs []types.Transaction,
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
		if !v.Pending {
			continue
		}
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
			CreatedAt: getCreatedAtFromExpiry(roundLifetime, *v.ExpiresAt),
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
