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
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/redemption"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	log "github.com/sirupsen/logrus"
)

type bitcoinReceiver struct {
	to     string
	amount uint64
}

func NewBitcoinReceiver(to string, amount uint64) Receiver {
	return bitcoinReceiver{to, amount}
}

func (r bitcoinReceiver) To() string {
	return r.to
}

func (r bitcoinReceiver) Amount() uint64 {
	return r.amount
}

func (r bitcoinReceiver) IsOnchain() bool {
	_, err := btcutil.DecodeAddress(r.to, nil)
	return err == nil
}

type covenantlessArkClient struct {
	*arkClient
}

func NewCovenantlessClient(sdkStore types.Store) (ArkClient, error) {
	cfgData, err := sdkStore.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}

	if cfgData != nil {
		return nil, ErrAlreadyInitialized
	}

	return &covenantlessArkClient{
		&arkClient{
			store: sdkStore,
		},
	}, nil
}

func LoadCovenantlessClient(sdkStore types.Store) (ArkClient, error) {
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

	covenantlessClient := covenantlessArkClient{
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
		covenantlessClient.txStreamCtxCancel = txStreamCtxCancel
		go covenantlessClient.listenForTransactions(txStreamCtx)
		go covenantlessClient.listenForBoardingUtxos(txStreamCtx)
	}

	return &covenantlessClient, nil
}

func LoadCovenantlessClientWithWallet(
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

	covenantlessClient := covenantlessArkClient{
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
		covenantlessClient.txStreamCtxCancel = txStreamCtxCancel
		go covenantlessClient.listenForTransactions(txStreamCtx)
		go covenantlessClient.listenForBoardingUtxos(txStreamCtx)
	}

	return &covenantlessClient, nil
}

func (a *covenantlessArkClient) Init(ctx context.Context, args InitArgs) error {
	if err := a.arkClient.init(ctx, args); err != nil {
		return err
	}

	if args.ListenTransactionStream {
		txStreamCtx, txStreamCtxCancel := context.WithCancel(context.Background())
		a.txStreamCtxCancel = txStreamCtxCancel
		go a.listenForTransactions(txStreamCtx)
		go a.listenForBoardingUtxos(txStreamCtx)
	}

	return nil
}

func (a *covenantlessArkClient) InitWithWallet(ctx context.Context, args InitWithWalletArgs) error {
	if err := a.arkClient.initWithWallet(ctx, args); err != nil {
		return err
	}

	if a.WithTransactionFeed {
		txStreamCtx, txStreamCtxCancel := context.WithCancel(context.Background())
		a.txStreamCtxCancel = txStreamCtxCancel
		go a.listenForTransactions(txStreamCtx)
		go a.listenForBoardingUtxos(txStreamCtx)
	}

	return nil
}

func (a *covenantlessArkClient) listenForTransactions(ctx context.Context) {
	eventChan, closeFunc, err := a.client.GetTransactionsStream(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to get transaction stream")
		return
	}
	defer closeFunc()

	offchainAddr, _, err := a.wallet.NewAddress(ctx, true)
	if err != nil {
		log.WithError(err).Error("Failed to get new address")
		return
	}

	addr, err := common.DecodeAddress(offchainAddr.Address)
	if err != nil {
		log.WithError(err).Error("Failed to decode address")
		return
	}

	addrPubkey := hex.EncodeToString(schnorr.SerializePubKey(addr.VtxoTapKey))

	for {
		select {
		case event, ok := <-eventChan:
			if !ok {
				continue
			}

			if event.Err != nil {
				log.WithError(event.Err).Error("Error in transaction stream")
				continue
			}

			newPendingBoardingTxs, err := a.getBoardingPendingTransactions(ctx)
			if err != nil {
				log.WithError(err).Error("Failed to get pending transactions")
				continue
			}

			if err := a.store.TransactionStore().
				AddTransactions(ctx, newPendingBoardingTxs); err != nil {
				log.WithError(err).Error("Failed to insert new boarding transactions")
				continue
			}

			a.processTransactionEvent(addrPubkey, event)
		case <-ctx.Done():
			return
		}
	}
}

func (a *covenantlessArkClient) listenForBoardingUtxos(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			newPendingBoardingTxs, err := a.getBoardingPendingTransactions(ctx)
			if err != nil {
				log.WithError(err).Error("Failed to get pending transactions")
				continue
			}

			if err := a.store.TransactionStore().
				AddTransactions(ctx, newPendingBoardingTxs); err != nil {
				log.WithError(err).Error("Failed to insert new boarding transactions")
				continue
			}
		case <-ctx.Done():
			return
		}
	}
}

func (a *covenantlessArkClient) getBoardingPendingTransactions(
	ctx context.Context,
) ([]types.Transaction, error) {
	oldTxs, err := a.store.TransactionStore().GetAllTransactions(ctx)
	if err != nil {
		return nil, err
	}

	boardingUtxos, err := a.getClaimableBoardingUtxos(ctx, nil)
	if err != nil {
		return nil, err
	}

	newPendingBoardingTxs := make([]types.Transaction, 0)
	for _, u := range boardingUtxos {
		found := false
		for _, tx := range oldTxs {
			if tx.BoardingTxid == u.Txid {
				found = true
				break
			}
		}

		if found {
			continue
		}

		newPendingBoardingTxs = append(newPendingBoardingTxs, types.Transaction{
			TransactionKey: types.TransactionKey{
				BoardingTxid: u.Txid,
			},
			Amount:    u.Amount,
			Type:      types.TxReceived,
			CreatedAt: u.CreatedAt,
		})
	}

	return newPendingBoardingTxs, nil
}

func (a *covenantlessArkClient) processTransactionEvent(
	pubkey string,
	event client.TransactionEvent,
) {
	if event.Round != nil {
		allTxs, err := a.store.TransactionStore().GetAllTransactions(context.Background())
		if err != nil {
			log.WithError(err).Error("Failed to get all transactions")
			return
		}
		pendingBoardingTxs := make(map[string]types.Transaction)
		for _, tx := range allTxs {
			if tx.BoardingTxid != "" && !tx.Settled {
				pendingBoardingTxs[tx.BoardingTxid] = tx
			}
		}
		var ignoreNewTxs bool
		settledBoardingTxs := make([]types.Transaction, 0, len(event.Round.ClaimedBoardingUtxos))
		for _, u := range event.Round.ClaimedBoardingUtxos {
			if tx, ok := pendingBoardingTxs[u.Txid]; ok {
				ignoreNewTxs = true
				tx.Settled = true
				settledBoardingTxs = append(settledBoardingTxs, tx)
			}
		}

		if len(settledBoardingTxs) > 0 {
			if err := a.store.TransactionStore().
				UpdateTransactions(context.Background(), settledBoardingTxs); err != nil {
				log.WithError(err).Error("Failed to settle boarding transactions")
				return
			}
		}

		spentKeys := make([]types.VtxoKey, 0, len(event.Round.SpentVtxos))
		for _, v := range event.Round.SpentVtxos {
			spentKeys = append(spentKeys, types.VtxoKey{
				Txid: v.Txid,
				VOut: v.VOut,
			})
		}

		vtxos, err := a.store.VtxoStore().
			GetVtxos(context.Background(), spentKeys)
		if err != nil {
			log.WithError(err).Error("Failed to get spent vtxos")
			return
		}

		if len(vtxos) > 0 {
			vtxosToUpdate := make([]types.Vtxo, 0)
			for _, v := range vtxos {
				v.Spent = true
				v.Pending = false
				vtxosToUpdate = append(vtxosToUpdate, v)
			}

			if err := a.store.VtxoStore().
				UpdateVtxos(context.Background(), vtxosToUpdate); err != nil {
				log.WithError(err).Error("Failed to update spent vtxos")
			}
		}

		vtxosToInsert := make([]types.Vtxo, 0)
		txsToInsert := make([]types.Transaction, 0)
		for _, v := range event.Round.SpendableVtxos {
			if v.Pubkey == pubkey {
				vtxosToInsert = append(vtxosToInsert, types.Vtxo{
					VtxoKey: types.VtxoKey{
						Txid: v.Txid,
						VOut: v.VOut,
					},
					Amount:    v.Amount,
					ExpiresAt: v.ExpiresAt,
					RedeemTx:  event.Round.Txid,
					Pending:   false,
					SpentBy:   v.SpentBy,
					Spent:     false,
				})

				if !ignoreNewTxs {
					txsToInsert = append(txsToInsert, types.Transaction{
						TransactionKey: types.TransactionKey{
							RoundTxid: event.Round.Txid,
						},
						Amount:    v.Amount,
						Type:      types.TxReceived,
						CreatedAt: time.Now(), //TODO is this ok?
					})
				}
			}
		}

		if len(vtxosToInsert) > 0 {
			if err := a.store.VtxoStore().
				AddVtxos(context.Background(), vtxosToInsert); err != nil {
				log.WithError(err).Error("Failed to insert new vtxos")
				return
			}
		}

		if len(txsToInsert) > 0 {
			if err := a.store.TransactionStore().
				AddTransactions(context.Background(), txsToInsert); err != nil {
				log.WithError(err).Error("Failed to insert received transaction")
				return
			}
		}
	}

	if event.Redeem != nil {
		vtxosToInsert := make([]types.Vtxo, 0)
		spentKeys := make([]types.VtxoKey, 0, len(event.Redeem.SpentVtxos))
		for _, v := range event.Redeem.SpentVtxos {
			spentKeys = append(spentKeys, types.VtxoKey{
				Txid: v.Txid,
				VOut: v.VOut,
			})
		}

		vtxos, err := a.store.VtxoStore().
			GetVtxos(context.Background(), spentKeys)
		if err != nil {
			log.WithError(err).Error("Failed to get spent vtxos")
			return
		}

		if len(vtxos) > 0 {
			inputAmount := uint64(0)
			vtxosToUpdate := make([]types.Vtxo, 0)
			for _, v := range vtxos {
				v.Spent = true
				vtxosToUpdate = append(vtxosToUpdate, v)
				inputAmount += v.Amount
			}

			if err := a.store.VtxoStore().
				UpdateVtxos(context.Background(), vtxosToUpdate); err != nil {
				log.WithError(err).Error("Failed to update spent vtxos")
				return
			}

			outputAmount := uint64(0)
			for _, v := range event.Redeem.SpendableVtxos {
				if v.Pubkey == pubkey {
					vtxosToInsert = append(vtxosToInsert, types.Vtxo{
						VtxoKey: types.VtxoKey{
							Txid: v.Txid,
							VOut: v.VOut,
						},
						Amount:    v.Amount,
						ExpiresAt: v.ExpiresAt,
						RedeemTx:  event.Redeem.Txid,
						Pending:   true,
						SpentBy:   v.SpentBy,
						Spent:     false,
					})
					outputAmount += v.Amount
				}
			}

			tx := types.Transaction{
				TransactionKey: types.TransactionKey{
					RedeemTxid: event.Redeem.Txid,
				},
				Amount:    inputAmount - outputAmount,
				Type:      types.TxSent,
				CreatedAt: time.Now(), //TODO is this ok?
			}

			if err := a.store.TransactionStore().
				AddTransactions(context.Background(), []types.Transaction{tx}); err != nil {
				log.WithError(err).Error("Failed to insert received transaction")
			}
		} else {
			for _, v := range event.Redeem.SpendableVtxos {
				if v.Pubkey == pubkey {
					vtxosToInsert = append(vtxosToInsert, types.Vtxo{
						VtxoKey: types.VtxoKey{
							Txid: v.Txid,
							VOut: v.VOut,
						},
						Amount:    v.Amount,
						ExpiresAt: v.ExpiresAt,
						RedeemTx:  event.Redeem.Txid,
						Pending:   true,
						SpentBy:   v.SpentBy,
						Spent:     false,
					})

					tx := types.Transaction{
						TransactionKey: types.TransactionKey{
							RedeemTxid: event.Redeem.Txid,
						},
						Amount:    v.Amount,
						Type:      types.TxReceived,
						CreatedAt: time.Now(), //TODO is this ok?
					}
					if err := a.store.TransactionStore().
						AddTransactions(context.Background(), []types.Transaction{tx}); err != nil {
						log.WithError(err).Error("Failed to insert received transaction")
					}
				}
			}
		}

		if err := a.store.VtxoStore().
			AddVtxos(context.Background(), vtxosToInsert); err != nil {
			log.WithError(err).Error("Failed to insert new vtxos")
			return
		}
	}
}

func (a *covenantlessArkClient) Balance(
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

func (a *covenantlessArkClient) SendOnChain(
	ctx context.Context, receivers []Receiver,
) (string, error) {
	for _, receiver := range receivers {
		if !receiver.IsOnchain() {
			return "", fmt.Errorf("invalid receiver address '%s': must be onchain", receiver.To())
		}
	}

	return a.sendOnchain(ctx, receivers)
}

func (a *covenantlessArkClient) SendOffChain(
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

func (a *covenantlessArkClient) Settle(ctx context.Context) (string, error) {
	return a.sendOffchain(ctx, false, nil)
}

func (a *covenantlessArkClient) UnilateralRedeem(ctx context.Context) error {
	if a.wallet.IsLocked() {
		return fmt.Errorf("wallet is locked")
	}

	vtxos, err := a.getVtxos(ctx, nil)
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

func (a *covenantlessArkClient) CollaborativeRedeem(
	ctx context.Context,
	addr string, amount uint64, withExpiryCoinselect bool,
) (string, error) {
	if a.wallet.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

	netParams := utils.ToBitcoinNetwork(a.Network)
	if _, err := btcutil.DecodeAddress(addr, &netParams); err != nil {
		return "", fmt.Errorf("invalid onchain address")
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
	spendableVtxos, err := a.getVtxos(ctx, nil)
	if err != nil {
		return "", err
	}

	for _, offchainAddr := range offchainAddrs {
		for _, v := range spendableVtxos {
			vtxoAddr, err := v.Address(a.AspPubkey, a.Network)
			if err != nil {
				return "", err
			}

			if vtxoAddr == offchainAddr.Address {
				vtxos = append(vtxos, client.DescriptorVtxo{
					Vtxo:       v,
					Descriptor: offchainAddr.Descriptor,
				})
			}
		}
	}

	boardingUtxos, err := a.getClaimableBoardingUtxos(ctx, nil)
	if err != nil {
		return "", err
	}

	selectedBoardingCoins, selectedCoins, changeAmount, err := utils.CoinSelect(
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

	inputs := make([]client.Input, 0, len(selectedCoins)+len(selectedBoardingCoins))

	for _, coin := range selectedCoins {
		inputs = append(inputs, client.Input{
			Outpoint: client.Outpoint{
				Txid: coin.Txid,
				VOut: coin.VOut,
			},
			Descriptor: coin.Descriptor,
		})
	}
	for _, coin := range selectedBoardingCoins {
		inputs = append(inputs, client.Input{
			Outpoint: client.Outpoint{
				Txid: coin.Txid,
				VOut: coin.VOut,
			},
			Descriptor: coin.Descriptor,
		})
	}

	roundEphemeralKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return "", err
	}

	paymentID, err := a.client.RegisterInputsForNextRound(
		ctx,
		inputs,
		hex.EncodeToString(roundEphemeralKey.PubKey().SerializeCompressed()),
	)
	if err != nil {
		return "", err
	}

	if err := a.client.RegisterOutputsForNextRound(ctx, paymentID, receivers); err != nil {
		return "", err
	}

	poolTxID, err := a.handleRoundStream(
		ctx, paymentID, selectedCoins, selectedBoardingCoins, receivers, roundEphemeralKey,
	)
	if err != nil {
		return "", err
	}

	return poolTxID, nil
}

func (a *covenantlessArkClient) SendAsync(
	ctx context.Context,
	withExpiryCoinselect bool, receivers []Receiver,
) (string, error) {
	if len(receivers) <= 0 {
		return "", fmt.Errorf("missing receivers")
	}

	netParams := utils.ToBitcoinNetwork(a.Network)
	for _, receiver := range receivers {
		isOnchain, _, err := utils.ParseBitcoinAddress(receiver.To(), netParams)
		if err != nil {
			return "", err
		}
		if isOnchain {
			return "", fmt.Errorf("all receiver addresses must be offchain addresses")
		}
	}

	offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}

	expectedAspPubKey := schnorr.SerializePubKey(a.AspPubkey)

	receiversOutput := make([]client.Output, 0)
	sumOfReceivers := uint64(0)

	for _, receiver := range receivers {
		rcvAddr, err := common.DecodeAddress(receiver.To())
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		rcvAspPubKey := schnorr.SerializePubKey(rcvAddr.Asp)

		if !bytes.Equal(expectedAspPubKey, rcvAspPubKey) {
			return "", fmt.Errorf("invalid receiver address '%s': expected ASP %s, got %s", receiver.To(), hex.EncodeToString(expectedAspPubKey), hex.EncodeToString(rcvAspPubKey))
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
	opts := &CoinSelectOptions{
		WithExpirySorting: withExpiryCoinselect,
	}
	spendableVtxos, err := a.getVtxos(ctx, opts)
	if err != nil {
		return "", err
	}

	for _, offchainAddr := range offchainAddrs {
		for _, v := range spendableVtxos {
			vtxoAddr, err := v.Address(a.AspPubkey, a.Network)
			if err != nil {
				return "", err
			}

			if vtxoAddr == offchainAddr.Address {
				vtxos = append(vtxos, client.DescriptorVtxo{
					Vtxo:       v,
					Descriptor: offchainAddr.Descriptor,
				})
			}
		}
	}

	// do not include boarding utxos
	_, selectedCoins, changeAmount, err := utils.CoinSelect(
		nil, vtxos, sumOfReceivers, a.Dust, withExpiryCoinselect,
	)
	if err != nil {
		return "", err
	}

	if changeAmount > 0 {
		changeReceiver := client.Output{
			Address: offchainAddrs[0].Address,
			Amount:  changeAmount,
		}
		receiversOutput = append(receiversOutput, changeReceiver)
	}

	inputs := make([]client.AsyncPaymentInput, 0, len(selectedCoins))

	for _, coin := range selectedCoins {
		vtxoScript, err := bitcointree.ParseVtxoScript(coin.Descriptor)
		if err != nil {
			return "", err
		}

		var forfeitClosure bitcointree.Closure

		switch s := vtxoScript.(type) {
		case *bitcointree.DefaultVtxoScript:
			forfeitClosure = &bitcointree.MultisigClosure{
				Pubkey:    s.Owner,
				AspPubkey: s.Asp,
			}
		default:
			return "", fmt.Errorf("unsupported vtxo script: %T", s)
		}

		forfeitLeaf, err := forfeitClosure.Leaf()
		if err != nil {
			return "", err
		}

		inputs = append(inputs, client.AsyncPaymentInput{
			Input: client.Input{
				Outpoint: client.Outpoint{
					Txid: coin.Txid,
					VOut: coin.VOut,
				},
				Descriptor: coin.Descriptor,
			},
			ForfeitLeafHash: forfeitLeaf.TapHash(),
		})
	}

	redeemTx, err := a.client.CreatePayment(ctx, inputs, receiversOutput)
	if err != nil {
		return "", err
	}

	// TODO verify the redeem tx signature

	signedRedeemTx, err := a.wallet.SignTransaction(ctx, a.explorer, redeemTx)
	if err != nil {
		return "", err
	}

	if err = a.client.CompletePayment(
		ctx, signedRedeemTx,
	); err != nil {
		return "", err
	}

	return signedRedeemTx, nil
}

func (a *covenantlessArkClient) GetTransactionHistory(
	ctx context.Context,
) ([]types.Transaction, error) {
	if a.Config.WithTransactionFeed {
		return a.store.TransactionStore().GetAllTransactions(ctx)
	}

	if a.Config == nil {
		return nil, fmt.Errorf("client not initialized")
	}

	spendableVtxos, spentVtxos, err := a.ListVtxos(ctx)
	if err != nil {
		return nil, err
	}

	boardingTxs, ignoreVtxos, err := a.getBoardingTxs(ctx)
	if err != nil {
		return nil, err
	}

	offchainTxs, err := vtxosToTxsCovenantless(
		a.Config.RoundLifetime, spendableVtxos, spentVtxos, ignoreVtxos,
	)
	if err != nil {
		return nil, err
	}

	txs := append(boardingTxs, offchainTxs...)
	// Sort the slice by age
	sort.Slice(txs, func(i, j int) bool {
		txi := txs[i]
		txj := txs[j]
		if txi.CreatedAt.Equal(txj.CreatedAt) {
			return txi.Type > txj.Type
		}
		return txi.CreatedAt.After(txj.CreatedAt)
	})

	return txs, nil
}

func (a *covenantlessArkClient) sendOnchain(
	ctx context.Context, receivers []Receiver,
) (string, error) {
	if a.wallet.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

	ptx, err := psbt.New(nil, nil, 2, 0, nil)
	if err != nil {
		return "", err
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return "", err
	}

	netParams := utils.ToBitcoinNetwork(a.Network)

	targetAmount := uint64(0)
	for _, receiver := range receivers {
		targetAmount += receiver.Amount()
		if receiver.Amount() < a.Dust {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount(), a.Dust)
		}

		rcvAddr, err := btcutil.DecodeAddress(receiver.To(), &netParams)
		if err != nil {
			return "", err
		}

		pkscript, err := txscript.PayToAddrScript(rcvAddr)
		if err != nil {
			return "", err
		}

		updater.Upsbt.UnsignedTx.AddTxOut(&wire.TxOut{
			Value:    int64(receiver.Amount()),
			PkScript: pkscript,
		})
		updater.Upsbt.Outputs = append(updater.Upsbt.Outputs, psbt.POutput{})
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
		addr, _ := btcutil.DecodeAddress(changeAddr.Address, &netParams)

		pkscript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return "", err
		}

		updater.Upsbt.UnsignedTx.AddTxOut(&wire.TxOut{
			Value:    int64(change),
			PkScript: pkscript,
		})
		updater.Upsbt.Outputs = append(updater.Upsbt.Outputs, psbt.POutput{})
	}

	size := updater.Upsbt.UnsignedTx.SerializeSize()
	feeRate, err := a.explorer.GetFeeRate()
	if err != nil {
		return "", err
	}

	feeAmount := uint64(math.Ceil(float64(size)*feeRate) + 50)

	if change > feeAmount {
		updater.Upsbt.UnsignedTx.TxOut[len(updater.Upsbt.Outputs)-1].Value = int64(change - feeAmount)
	} else if change == feeAmount {
		updater.Upsbt.UnsignedTx.TxOut = updater.Upsbt.UnsignedTx.TxOut[:len(updater.Upsbt.UnsignedTx.TxOut)-1]
	} else { // change < feeAmount
		if change > 0 {
			updater.Upsbt.UnsignedTx.TxOut = updater.Upsbt.UnsignedTx.TxOut[:len(updater.Upsbt.UnsignedTx.TxOut)-1]
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
			addr, _ := btcutil.DecodeAddress(changeAddr.Address, &netParams)

			pkscript, err := txscript.PayToAddrScript(addr)
			if err != nil {
				return "", err
			}

			updater.Upsbt.UnsignedTx.AddTxOut(&wire.TxOut{
				Value:    int64(newChange),
				PkScript: pkscript,
			})
			updater.Upsbt.Outputs = append(updater.Upsbt.Outputs, psbt.POutput{})
		}
	}

	unsignedTx, _ := ptx.B64Encode()

	signedTx, err := a.wallet.SignTransaction(ctx, a.explorer, unsignedTx)
	if err != nil {
		return "", err
	}

	ptx, err = psbt.NewFromRawBytes(strings.NewReader(signedTx), true)
	if err != nil {
		return "", err
	}

	for i := range ptx.Inputs {
		if err := psbt.Finalize(ptx, i); err != nil {
			return "", err
		}
	}

	return ptx.B64Encode()
}

func (a *covenantlessArkClient) sendOffchain(
	ctx context.Context, withExpiryCoinselect bool, receivers []Receiver,
) (string, error) {
	if a.wallet.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

	expectedAspPubKey := schnorr.SerializePubKey(a.AspPubkey)
	outputs := make([]client.Output, 0)
	sumOfReceivers := uint64(0)

	// validate receivers and create outputs
	for _, receiver := range receivers {
		rcvAddr, err := common.DecodeAddress(receiver.To())
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		rcvAspPubKey := schnorr.SerializePubKey(rcvAddr.Asp)

		if !bytes.Equal(expectedAspPubKey, rcvAspPubKey) {
			return "", fmt.Errorf("invalid receiver address '%s': expected ASP %s, got %s", receiver.To(), hex.EncodeToString(expectedAspPubKey), hex.EncodeToString(rcvAspPubKey))
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

	vtxos := make([]client.DescriptorVtxo, 0)
	opts := &CoinSelectOptions{
		WithExpirySorting: withExpiryCoinselect}
	spendableVtxos, err := a.getVtxos(ctx, opts)
	if err != nil {
		return "", err
	}

	for _, offchainAddr := range offchainAddrs {
		for _, v := range spendableVtxos {
			vtxoAddr, err := v.Address(a.AspPubkey, a.Network)
			if err != nil {
				return "", err
			}

			if vtxoAddr == offchainAddr.Address {
				vtxos = append(vtxos, client.DescriptorVtxo{
					Vtxo:       v,
					Descriptor: offchainAddr.Descriptor,
				})
			}
		}
	}

	boardingUtxos, err := a.getClaimableBoardingUtxos(ctx, nil)
	if err != nil {
		return "", err
	}

	var selectedBoardingCoins []types.Utxo
	var selectedCoins []client.DescriptorVtxo
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
			Descriptor: coin.Descriptor,
		})
	}
	for _, boardingUtxo := range selectedBoardingCoins {
		inputs = append(inputs, client.Input{
			Outpoint: client.Outpoint{
				Txid: boardingUtxo.Txid,
				VOut: boardingUtxo.VOut,
			},
			Descriptor: boardingUtxo.Descriptor,
		})
	}

	roundEphemeralKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return "", err
	}

	paymentID, err := a.client.RegisterInputsForNextRound(
		ctx, inputs, hex.EncodeToString(roundEphemeralKey.PubKey().SerializeCompressed()),
	)
	if err != nil {
		return "", err
	}

	if err := a.client.RegisterOutputsForNextRound(
		ctx, paymentID, outputs,
	); err != nil {
		return "", err
	}

	log.Infof("payment registered with id: %s", paymentID)

	poolTxID, err := a.handleRoundStream(
		ctx, paymentID, selectedCoins, selectedBoardingCoins, outputs, roundEphemeralKey,
	)
	if err != nil {
		return "", err
	}

	return poolTxID, nil
}

func (a *covenantlessArkClient) addInputs(
	ctx context.Context,
	updater *psbt.Updater,
	utxos []types.Utxo,
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
		previousHash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return err
		}

		sequence, err := utxo.Sequence()
		if err != nil {
			return err
		}

		updater.Upsbt.UnsignedTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *previousHash,
				Index: utxo.VOut,
			},
			Sequence: sequence,
		})

		vtxoScript := &bitcointree.DefaultVtxoScript{
			Owner:     userPubkey,
			Asp:       aspPubkey,
			ExitDelay: utxo.Delay,
		}

		exitClosure := &bitcointree.CSVSigClosure{
			Pubkey:  userPubkey,
			Seconds: uint(utxo.Delay),
		}

		exitLeaf, err := exitClosure.Leaf()
		if err != nil {
			return err
		}

		_, taprootTree, err := vtxoScript.TapTree()
		if err != nil {
			return err
		}

		leafProof, err := taprootTree.GetTaprootMerkleProof(exitLeaf.TapHash())
		if err != nil {
			return fmt.Errorf("failed to get taproot merkle proof: %s", err)
		}

		updater.Upsbt.Inputs = append(updater.Upsbt.Inputs, psbt.PInput{
			TaprootLeafScript: []*psbt.TaprootTapLeafScript{
				{
					ControlBlock: leafProof.ControlBlock,
					Script:       leafProof.Script,
					LeafVersion:  txscript.BaseLeafVersion,
				},
			},
		})
	}

	return nil
}

func (a *covenantlessArkClient) handleRoundStream(
	ctx context.Context,
	paymentID string,
	vtxosToSign []client.DescriptorVtxo,
	boardingUtxos []types.Utxo,
	receivers []client.Output,
	roundEphemeralKey *secp256k1.PrivateKey,
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

	var signerSession bitcointree.SignerSession

	const (
		start = iota
		roundSigningStarted
		roundSigningNoncesGenerated
		roundFinalization
	)

	step := start

	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("context done %s", ctx.Err())
		case notify := <-eventsCh:
			if notify.Err != nil {
				return "", notify.Err
			}
			switch event := notify.Event; event.(type) {
			case client.RoundFinalizedEvent:
				if step != roundFinalization {
					continue
				}
				return event.(client.RoundFinalizedEvent).Txid, nil
			case client.RoundFailedEvent:
				return "", fmt.Errorf("round failed: %s", event.(client.RoundFailedEvent).Reason)
			case client.RoundSigningStartedEvent:
				pingStop()
				if step != start {
					continue
				}
				log.Info("a round signing started")
				signerSession, err = a.handleRoundSigningStarted(
					ctx, roundEphemeralKey, event.(client.RoundSigningStartedEvent),
				)
				if err != nil {
					return "", err
				}
				step++
				continue
			case client.RoundSigningNoncesGeneratedEvent:
				if step != roundSigningStarted {
					continue
				}
				pingStop()
				log.Info("round combined nonces generated")
				if err := a.handleRoundSigningNoncesGenerated(
					ctx, event.(client.RoundSigningNoncesGeneratedEvent), roundEphemeralKey, signerSession,
				); err != nil {
					return "", err
				}
				step++
				continue
			case client.RoundFinalizationEvent:
				if step != roundSigningNoncesGenerated {
					continue
				}
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

				log.Info("finalizing payment... ")
				if err := a.client.SubmitSignedForfeitTxs(ctx, signedForfeitTxs, signedRoundTx); err != nil {
					return "", err
				}

				log.Info("done.")
				log.Info("waiting for round finalization...")
				step++
				continue
			}
		}
	}
}

func (a *covenantlessArkClient) handleRoundSigningStarted(
	ctx context.Context, ephemeralKey *secp256k1.PrivateKey, event client.RoundSigningStartedEvent,
) (signerSession bitcointree.SignerSession, err error) {
	sweepClosure := bitcointree.CSVSigClosure{
		Pubkey:  a.AspPubkey,
		Seconds: uint(a.RoundLifetime),
	}

	sweepTapLeaf, err := sweepClosure.Leaf()
	if err != nil {
		return
	}

	roundTx, err := psbt.NewFromRawBytes(strings.NewReader(event.UnsignedRoundTx), true)
	if err != nil {
		return
	}

	sharedOutput := roundTx.UnsignedTx.TxOut[0]
	sharedOutputValue := sharedOutput.Value

	sweepTapTree := txscript.AssembleTaprootScriptTree(*sweepTapLeaf)
	root := sweepTapTree.RootNode.TapHash()

	signerSession = bitcointree.NewTreeSignerSession(
		ephemeralKey, sharedOutputValue, event.UnsignedTree, root.CloneBytes(),
	)

	if err = signerSession.SetKeys(event.CosignersPublicKeys); err != nil {
		return
	}

	nonces, err := signerSession.GetNonces()
	if err != nil {
		return
	}

	myPubKey := hex.EncodeToString(ephemeralKey.PubKey().SerializeCompressed())

	err = a.arkClient.client.SubmitTreeNonces(ctx, event.ID, myPubKey, nonces)

	return
}

func (a *covenantlessArkClient) handleRoundSigningNoncesGenerated(
	ctx context.Context,
	event client.RoundSigningNoncesGeneratedEvent,
	ephemeralKey *secp256k1.PrivateKey,
	signerSession bitcointree.SignerSession,
) error {
	if signerSession == nil {
		return fmt.Errorf("tree signer session not set")
	}

	if err := signerSession.SetAggregatedNonces(event.Nonces); err != nil {
		return err
	}

	sigs, err := signerSession.Sign()
	if err != nil {
		return err
	}

	if err := a.arkClient.client.SubmitTreeSignatures(
		ctx,
		event.ID,
		hex.EncodeToString(ephemeralKey.PubKey().SerializeCompressed()),
		sigs,
	); err != nil {
		return err
	}

	return nil
}

func (a *covenantlessArkClient) handleRoundFinalization(
	ctx context.Context,
	event client.RoundFinalizationEvent,
	vtxos []client.DescriptorVtxo,
	boardingUtxos []types.Utxo,
	receivers []client.Output,
) ([]string, string, error) {
	if err := a.validateCongestionTree(event, receivers); err != nil {
		return nil, "", fmt.Errorf("failed to verify congestion tree: %s", err)
	}

	var forfeits []string

	if len(vtxos) > 0 {
		signedForfeits, err := a.createAndSignForfeits(
			ctx, vtxos, event.Connectors, event.MinRelayFeeRate,
		)
		if err != nil {
			return nil, "", err
		}

		forfeits = signedForfeits
	}

	// if no boarding utxos inputs, we don't need to sign the round transaction
	if len(boardingUtxos) <= 0 {
		return forfeits, "", nil
	}

	roundPtx, err := psbt.NewFromRawBytes(strings.NewReader(event.Tx), true)
	if err != nil {
		return nil, "", err
	}

	for _, boardingUtxo := range boardingUtxos {
		boardingVtxoScript, err := bitcointree.ParseVtxoScript(boardingUtxo.Descriptor)
		if err != nil {
			return nil, "", err
		}

		var myPubkey *secp256k1.PublicKey

		switch v := boardingVtxoScript.(type) {
		case *bitcointree.DefaultVtxoScript:
			myPubkey = v.Owner
		default:
			return nil, "", fmt.Errorf("unsupported boarding descriptor: %s", boardingUtxo.Descriptor)
		}

		// add tapscript leaf
		forfeitClosure := &bitcointree.MultisigClosure{
			Pubkey:    myPubkey,
			AspPubkey: a.AspPubkey,
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
			return nil, "", fmt.Errorf("failed to get taproot merkle proof for boarding utxo: %s", err)
		}

		tapscript := &psbt.TaprootTapLeafScript{
			ControlBlock: forfeitProof.ControlBlock,
			Script:       forfeitProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		}

		for i := range roundPtx.Inputs {
			previousOutpoint := roundPtx.UnsignedTx.TxIn[i].PreviousOutPoint

			if boardingUtxo.Txid == previousOutpoint.Hash.String() && boardingUtxo.VOut == previousOutpoint.Index {
				roundPtx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapscript}
				break
			}
		}
	}

	b64, err := roundPtx.B64Encode()
	if err != nil {
		return nil, "", err
	}

	signedRoundTx, err := a.wallet.SignTransaction(ctx, a.explorer, b64)
	if err != nil {
		return nil, "", err
	}

	return forfeits, signedRoundTx, nil
}

func (a *covenantlessArkClient) validateCongestionTree(
	event client.RoundFinalizationEvent, receivers []client.Output,
) error {
	poolTx := event.Tx
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(poolTx), true)
	if err != nil {
		return err
	}

	if !utils.IsOnchainOnly(receivers) {
		if err := bitcointree.ValidateCongestionTree(
			event.Tree, poolTx, a.Config.AspPubkey, a.RoundLifetime,
		); err != nil {
			return err
		}
	}

	// if err := common.ValidateConnectors(poolTx, event.Connectors); err != nil {
	// 	return err
	// }

	if err := a.validateReceivers(
		ptx, receivers, event.Tree,
	); err != nil {
		return err
	}

	log.Info("congestion tree validated")

	return nil
}

func (a *covenantlessArkClient) validateReceivers(
	ptx *psbt.Packet,
	receivers []client.Output,
	congestionTree tree.CongestionTree,
) error {
	netParams := utils.ToBitcoinNetwork(a.Network)
	for _, receiver := range receivers {
		isOnChain, onchainScript, err := utils.ParseBitcoinAddress(
			receiver.Address, netParams,
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

func (a *covenantlessArkClient) validateOnChainReceiver(
	ptx *psbt.Packet,
	receiver client.Output,
	onchainScript []byte,
) error {
	found := false
	for _, output := range ptx.UnsignedTx.TxOut {
		if bytes.Equal(output.PkScript, onchainScript) {
			if output.Value != int64(receiver.Amount) {
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

func (a *covenantlessArkClient) validateOffChainReceiver(
	congestionTree tree.CongestionTree,
	receiver client.Output,
) error {
	found := false

	rcvAddr, err := common.DecodeAddress(receiver.Address)
	if err != nil {
		return err
	}

	vtxoTapKey := schnorr.SerializePubKey(rcvAddr.VtxoTapKey)

	leaves := congestionTree.Leaves()
	for _, leaf := range leaves {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(leaf.Tx), true)
		if err != nil {
			return err
		}

		for _, output := range tx.UnsignedTx.TxOut {
			if len(output.PkScript) == 0 {
				continue
			}

			if bytes.Equal(output.PkScript[2:], vtxoTapKey) {
				if output.Value != int64(receiver.Amount) {
					continue
				}

				found = true
				break
			}
		}

		if found {
			break
		}
	}

	if !found {
		return fmt.Errorf(
			"off-chain send output not found: %s", receiver.Address,
		)
	}

	return nil
}

func (a *covenantlessArkClient) createAndSignForfeits(
	ctx context.Context,
	vtxosToSign []client.DescriptorVtxo,
	connectors []string,
	feeRate chainfee.SatPerKVByte,
) ([]string, error) {
	parsedForfeitAddr, err := btcutil.DecodeAddress(a.ForfeitAddress, nil)
	if err != nil {
		return nil, err
	}

	forfeitPkScript, err := txscript.PayToAddrScript(parsedForfeitAddr)
	if err != nil {
		return nil, err
	}

	parsedScript, err := txscript.ParsePkScript(forfeitPkScript)
	if err != nil {
		return nil, err
	}

	signedForfeits := make([]string, 0)
	connectorsPsets := make([]*psbt.Packet, 0, len(connectors))

	for _, connector := range connectors {
		p, err := psbt.NewFromRawBytes(strings.NewReader(connector), true)
		if err != nil {
			return nil, err
		}

		connectorsPsets = append(connectorsPsets, p)
	}

	for _, vtxo := range vtxosToSign {
		vtxoScript, err := bitcointree.ParseVtxoScript(vtxo.Descriptor)
		if err != nil {
			return nil, err
		}

		vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
		if err != nil {
			return nil, err
		}

		feeAmount, err := common.ComputeForfeitMinRelayFee(feeRate, vtxoTapTree, parsedScript.Class())
		if err != nil {
			return nil, err
		}

		vtxoOutputScript, err := common.P2TRScript(vtxoTapKey)
		if err != nil {
			return nil, err
		}

		vtxoTxHash, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return nil, err
		}

		vtxoInput := &wire.OutPoint{
			Hash:  *vtxoTxHash,
			Index: vtxo.VOut,
		}

		var forfeitClosure bitcointree.Closure

		switch v := vtxoScript.(type) {
		case *bitcointree.DefaultVtxoScript:
			forfeitClosure = &bitcointree.MultisigClosure{
				Pubkey:    v.Owner,
				AspPubkey: a.AspPubkey,
			}
		default:
			return nil, fmt.Errorf("unsupported vtxo script: %T", vtxoScript)
		}

		forfeitLeaf, err := forfeitClosure.Leaf()
		if err != nil {
			return nil, err
		}

		leafProof, err := vtxoTapTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
		if err != nil {
			return nil, err
		}

		tapscript := psbt.TaprootTapLeafScript{
			ControlBlock: leafProof.ControlBlock,
			Script:       leafProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		}

		for _, connectorPset := range connectorsPsets {
			forfeits, err := bitcointree.BuildForfeitTxs(
				connectorPset, vtxoInput, vtxo.Amount, a.Dust, feeAmount, vtxoOutputScript, forfeitPkScript,
			)
			if err != nil {
				return nil, err
			}

			if len(forfeits) <= 0 {
				return nil, fmt.Errorf("no forfeit txs created dust =  %d", a.Dust)
			}

			for _, forfeit := range forfeits {
				forfeit.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{&tapscript}

				b64, err := forfeit.B64Encode()
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

func (a *covenantlessArkClient) coinSelectOnchain(
	ctx context.Context, targetAmount uint64, exclude []types.Utxo,
) ([]types.Utxo, uint64, error) {
	_, boardingAddrs, redemptionAddrs, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, 0, err
	}

	now := time.Now()

	fetchedUtxos := make([]types.Utxo, 0)
	for _, addr := range boardingAddrs {
		boardingScript, err := bitcointree.ParseVtxoScript(addr.Descriptor)
		if err != nil {
			return nil, 0, err
		}

		var boardingTimeout uint

		if defaultVtxo, ok := boardingScript.(*bitcointree.DefaultVtxoScript); ok {
			boardingTimeout = defaultVtxo.ExitDelay
		} else {
			return nil, 0, fmt.Errorf("unsupported boarding descriptor: %s", addr.Descriptor)
		}
		utxos, err := a.explorer.GetUtxos(addr.Address)
		if err != nil {
			return nil, 0, err
		}

		for _, utxo := range utxos {
			u := utxo.ToUtxo(boardingTimeout, addr.Descriptor)
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
			u := utxo.ToUtxo(uint(a.UnilateralExitDelay), addr.Descriptor)
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

func (a *covenantlessArkClient) getRedeemBranches(
	ctx context.Context, vtxos []client.Vtxo,
) (map[string]*redemption.CovenantlessRedeemBranch, error) {
	congestionTrees := make(map[string]tree.CongestionTree, 0)
	redeemBranches := make(map[string]*redemption.CovenantlessRedeemBranch, 0)

	for i := range vtxos {
		vtxo := vtxos[i]

		// TODO: handle exit for pending changes
		if vtxo.RedeemTx != "" {
			continue
		}

		if _, ok := congestionTrees[vtxo.RoundTxid]; !ok {
			round, err := a.client.GetRound(ctx, vtxo.RoundTxid)
			if err != nil {
				return nil, err
			}

			congestionTrees[vtxo.RoundTxid] = round.Tree
		}

		redeemBranch, err := redemption.NewCovenantlessRedeemBranch(
			a.explorer, congestionTrees[vtxo.RoundTxid], vtxo,
		)
		if err != nil {
			return nil, err
		}

		redeemBranches[vtxo.Txid] = redeemBranch
	}

	return redeemBranches, nil
}

func (a *covenantlessArkClient) getOffchainBalance(
	ctx context.Context, computeVtxoExpiration bool,
) (uint64, map[int64]uint64, error) {
	amountByExpiration := make(map[int64]uint64, 0)
	opts := &CoinSelectOptions{
		WithExpirySorting: computeVtxoExpiration,
	}
	vtxos, err := a.getVtxos(ctx, opts)
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

func (a *covenantlessArkClient) getAllBoardingUtxos(
	ctx context.Context,
) ([]types.Utxo, map[string]struct{}, error) {
	_, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, nil, err
	}

	utxos := []types.Utxo{}
	ignoreVtxos := make(map[string]struct{}, 0)
	for _, addr := range boardingAddrs {
		txs, err := a.explorer.GetTxs(addr.Address)
		if err != nil {
			return nil, nil, err
		}
		for _, tx := range txs {
			for i, vout := range tx.Vout {
				var spent bool
				if vout.Address == addr.Address {
					spentStatuses, err := a.explorer.GetTxOutspends(tx.Txid)
					if err != nil {
						return nil, nil, err
					}
					if s := spentStatuses[i]; s.Spent {
						ignoreVtxos[s.SpentBy] = struct{}{}
						spent = true
					}
					createdAt := time.Time{}
					if tx.Status.Confirmed {
						createdAt = time.Unix(tx.Status.Blocktime, 0)
					}
					utxos = append(utxos, types.Utxo{
						Txid:       tx.Txid,
						VOut:       uint32(i),
						Amount:     vout.Amount,
						CreatedAt:  createdAt,
						Descriptor: addr.Descriptor,
						Spent:      spent,
					})
				}
			}
		}
	}

	return utxos, ignoreVtxos, nil
}

func (a *covenantlessArkClient) getClaimableBoardingUtxos(ctx context.Context, opts *CoinSelectOptions) ([]types.Utxo, error) {
	_, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	claimable := make([]types.Utxo, 0)

	for _, addr := range boardingAddrs {
		boardingScript, err := bitcointree.ParseVtxoScript(addr.Descriptor)
		if err != nil {
			return nil, err
		}

		var boardingTimeout uint

		if defaultVtxo, ok := boardingScript.(*bitcointree.DefaultVtxoScript); ok {
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

			u := utxo.ToUtxo(boardingTimeout, addr.Descriptor)
			if u.SpendableAt.Before(now) {
				continue
			}

			claimable = append(claimable, u)
		}
	}

	return claimable, nil
}

func (a *covenantlessArkClient) getVtxos(
	ctx context.Context, opts *CoinSelectOptions,
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
				spendableVtxos[i].ExpiresAt = expiration
				break
			}
		}
	}

	return spendableVtxos, nil
}

func (a *covenantlessArkClient) getBoardingTxs(
	ctx context.Context,
) ([]types.Transaction, map[string]struct{}, error) {
	allUtxos, ignoreVtxos, err := a.getAllBoardingUtxos(ctx)
	if err != nil {
		return nil, nil, err
	}

	unconfirmedTxs := make([]types.Transaction, 0)
	confirmedTxs := make([]types.Transaction, 0)
	for _, u := range allUtxos {
		tx := types.Transaction{
			TransactionKey: types.TransactionKey{
				BoardingTxid: u.Txid,
			},
			Amount:    u.Amount,
			Type:      types.TxReceived,
			CreatedAt: u.CreatedAt,
			Settled:   u.Spent,
		}

		emptyTime := time.Time{}
		if u.CreatedAt == emptyTime {
			unconfirmedTxs = append(unconfirmedTxs, tx)
			continue
		}
		confirmedTxs = append(confirmedTxs, tx)
	}

	txs := append(unconfirmedTxs, confirmedTxs...)
	return txs, ignoreVtxos, nil
}

func findVtxosBySpentBy(allVtxos []client.Vtxo, txid string) (vtxos []client.Vtxo) {
	for _, v := range allVtxos {
		if v.SpentBy == txid {
			vtxos = append(vtxos, v)
		}
	}
	return
}

func vtxosToTxsCovenantless(
	roundLifetime int64, spendable, spent []client.Vtxo, ignoreVtxos map[string]struct{},
) ([]types.Transaction, error) {
	transactions := make([]types.Transaction, 0)
	indexedTxs := make(map[string]types.Transaction)
	settledVtxos := make(map[string]struct{})

	// First, loop over all vtxos to find those that have been settled
	// (they have round txid instead of redeem tx)
	for _, v := range append(spendable, spent...) {
		_, ok1 := ignoreVtxos[v.Txid]
		_, ok2 := ignoreVtxos[v.RoundTxid]
		if ok1 || ok2 {
			continue
		}
		if len(v.RoundTxid) > 0 {
			settledVtxos[v.RoundTxid] = struct{}{}
		}
	}

	for _, v := range spent {
		// If the vtxo is settled, add the record to the tx history.
		if _, ok := settledVtxos[v.SpentBy]; ok {
			transactions = append(transactions, types.Transaction{
				TransactionKey: types.TransactionKey{
					RedeemTxid: v.Txid,
				},
				Amount:    v.Amount,
				Type:      types.TxReceived,
				CreatedAt: getCreatedAtFromExpiry(roundLifetime, *v.ExpiresAt),
				Settled:   true,
			})
			// Delete any duplicate in the indexed list.
			delete(indexedTxs, v.SpentBy)
			// Ignore the spendable vtxo created by the settlement.
			ignoreVtxos[v.SpentBy] = struct{}{}
			continue
		}

		// If this vtxo spent another one => subtract the amount to find the sent amount.
		if tx, ok := indexedTxs[v.Txid]; ok {
			tx.Amount -= v.Amount
			if v.RedeemTx == "" {
				tx.RedeemTxid = ""
			} else {
				tx.RoundTxid = ""
			}
			indexedTxs[v.Txid] = tx
		}

		// Add a transaction to the indexed list if not existing.
		// This is an intermediate tx state that is updated in the next iterations.
		tx, ok := indexedTxs[v.SpentBy]
		if !ok {
			indexedTxs[v.SpentBy] = types.Transaction{
				TransactionKey: types.TransactionKey{
					RedeemTxid: v.SpentBy,
					RoundTxid:  v.SpentBy,
				},
				Amount:    v.Amount,
				Type:      types.TxSent,
				CreatedAt: getCreatedAtFromExpiry(roundLifetime, *v.ExpiresAt),
			}
			continue
		}

		// Otherwise add the amount of this vtxo to the one of the tx in the indexed list.
		tx.Amount += v.Amount
		indexedTxs[v.SpentBy] = tx
	}

	for _, v := range spendable {
		// Ignore the vtxo eventually.
		_, ok1 := ignoreVtxos[v.Txid]
		_, ok2 := ignoreVtxos[v.RoundTxid]
		if ok1 || ok2 {
			continue
		}
		txid := v.RoundTxid
		if txid == "" {
			txid = v.Txid
		}

		tx, ok := indexedTxs[txid]
		// If there is no track of records, add a received tx record in the history.
		if !ok {
			redeemTxid := ""
			if v.RoundTxid == "" {
				redeemTxid = v.Txid
			}
			transactions = append(transactions, types.Transaction{
				TransactionKey: types.TransactionKey{
					RedeemTxid: redeemTxid,
					RoundTxid:  v.RoundTxid,
				},
				Amount:    v.Amount,
				Type:      types.TxReceived,
				CreatedAt: getCreatedAtFromExpiry(roundLifetime, *v.ExpiresAt),
			})
			continue
		}

		// Otherwise subtract the amount to find the actual spent amount.
		tx.Amount -= v.Amount
		if v.RedeemTx == "" {
			tx.RedeemTxid = ""
		} else {
			tx.RoundTxid = ""
		}
		indexedTxs[txid] = tx
	}

	for _, tx := range indexedTxs {
		transactions = append(transactions, tx)
	}

	return transactions, nil
}
