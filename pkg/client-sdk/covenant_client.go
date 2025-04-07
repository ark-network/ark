package arksdk

import (
	"context"
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
		return nil, fmt.Errorf("failed to setup wallet: %s", err)
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

func (a *covenantArkClient) OnboardAgainAllExpiredBoardings(
	ctx context.Context,
) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (a *covenantArkClient) WithdrawFromAllExpiredBoardings(
	ctx context.Context, to string,
) (string, error) {
	return "", fmt.Errorf("not implemented")
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

func (a *covenantArkClient) StartUnilateralExit(ctx context.Context) error {
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

func (a *covenantArkClient) CompleteUnilateralExit(
	ctx context.Context, to string,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	if _, err := address.ToOutputScript(to); err != nil {
		return "", fmt.Errorf("invalid receiver address '%s': must be onchain", to)
	}

	return a.completeUnilateralExit(ctx, to)
}

func (a *covenantArkClient) CollaborativeExit(
	ctx context.Context,
	addr string, amount uint64, withExpiryCoinselect bool,
	opts ...Option,
) (string, error) {
	return "", fmt.Errorf("not implemented")
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

func (a *covenantArkClient) RecoverSweptVtxos(ctx context.Context) (string, error) {
	return "", fmt.Errorf("not implemented")
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

func (a *covenantArkClient) completeUnilateralExit(
	ctx context.Context, to string,
) (string, error) {
	net := utils.ToElementsNetwork(a.Network)
	script, err := address.ToOutputScript(to)
	if err != nil {
		return "", err
	}

	_, _, redemptionAddrs, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}

	now := time.Now()
	spendableUtxos := make([]types.Utxo, 0)
	targetAmount := uint64(0)
	for _, addr := range redemptionAddrs {
		utxos, err := a.explorer.GetUtxos(addr.Address)
		if err != nil {
			return "", err
		}

		for _, utxo := range utxos {
			u := utxo.ToUtxo(a.UnilateralExitDelay, addr.Tapscripts)
			if u.SpendableAt.Before(now) || u.SpendableAt.Equal(now) {
				spendableUtxos = append(spendableUtxos, u)
				targetAmount += u.Amount
			}
		}
	}

	if targetAmount == 0 {
		return "", fmt.Errorf("no mature funds available")
	}

	pset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return "", err
	}
	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return "", err
	}

	if err := updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  net.AssetID,
			Amount: targetAmount,
			Script: script,
		},
	}); err != nil {
		return "", err
	}

	if err := a.addInputs(ctx, updater, spendableUtxos); err != nil {
		return "", err
	}

	utx, err := pset.UnsignedTx()
	if err != nil {
		return "", err
	}

	vBytes := utx.VirtualSize()
	feeAmount := uint64(math.Ceil(float64(vBytes) * 0.5))

	if targetAmount-feeAmount <= a.Dust {
		return "", fmt.Errorf("not enough mature funds to cover network fees")
	}

	if err := updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  net.AssetID,
			Amount: feeAmount,
		},
	}); err != nil {
		return "", err
	}
	pset.Outputs[0].Value -= feeAmount

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
	return "", fmt.Errorf("not implemented")
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

func (a *covenantArkClient) getRedeemBranches(
	ctx context.Context, vtxos []client.Vtxo,
) (map[string]*redemption.CovenantRedeemBranch, error) {
	vtxoTrees := make(map[string]tree.TxTree, 0)
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
			CreatedAt: v.CreatedAt,
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
