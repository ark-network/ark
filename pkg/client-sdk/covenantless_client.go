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

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils/redemption"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/address"
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

func (r bitcoinReceiver) isOnchain() bool {
	_, err := btcutil.DecodeAddress(r.to, nil)
	return err == nil
}

type covenantlessArkClient struct {
	*arkClient
}

func NewCovenantlessClient(storeSvc store.ConfigStore) (ArkClient, error) {
	data, err := storeSvc.GetData(context.Background())
	if err != nil {
		return nil, err
	}
	if data != nil {
		return nil, ErrAlreadyInitialized
	}

	return &covenantlessArkClient{&arkClient{store: storeSvc}}, nil
}

func LoadCovenantlessClient(storeSvc store.ConfigStore) (ArkClient, error) {
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

	clientSvc, err := getClient(
		supportedClients, data.ClientType, data.AspUrl,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup transport client: %s", err)
	}

	explorerSvc, err := getExplorer(supportedNetworks, data.Network.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to setup explorer: %s", err)
	}

	walletSvc, err := getWallet(storeSvc, data, supportedWallets)
	if err != nil {
		return nil, fmt.Errorf("faile to setup wallet: %s", err)
	}

	return &covenantlessArkClient{
		&arkClient{data, walletSvc, storeSvc, explorerSvc, clientSvc},
	}, nil
}

func LoadCovenantlessClientWithWallet(
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

	clientSvc, err := getClient(
		supportedClients, data.ClientType, data.AspUrl,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup transport client: %s", err)
	}

	explorerSvc, err := getExplorer(supportedNetworks, data.Network.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to setup explorer: %s", err)
	}

	return &covenantlessArkClient{
		&arkClient{data, walletSvc, storeSvc, explorerSvc, clientSvc},
	}, nil
}

func (a *covenantlessArkClient) Onboard(
	ctx context.Context, amount uint64,
) (string, error) {
	if amount <= 0 {
		return "", fmt.Errorf("invalid amount to onboard %d", amount)
	}

	offchainAddr, _, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", err
	}

	_, userPubkey, aspPubkey, _ := common.DecodeAddress(offchainAddr)
	userPubkeyStr := hex.EncodeToString(userPubkey.SerializeCompressed())

	congestionTreeLeaf := bitcointree.Receiver{
		Pubkey: userPubkeyStr,
		Amount: amount,
	}

	leaves := []bitcointree.Receiver{congestionTreeLeaf}

	ephemeralKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return "", err
	}

	cosigners := []*secp256k1.PublicKey{ephemeralKey.PubKey()} // TODO asp as cosigner

	sharedOutputScript, sharedOutputAmount, err := bitcointree.CraftSharedOutput(
		cosigners,
		aspPubkey,
		leaves,
		a.MinRelayFee,
		a.RoundLifetime,
		a.UnilateralExitDelay,
	)
	if err != nil {
		return "", err
	}

	netParams := utils.ToBitcoinNetwork(a.Network)

	address, err := btcutil.NewAddressTaproot(sharedOutputScript[2:], &netParams)
	if err != nil {
		return "", err
	}

	onchainReceiver := NewBitcoinReceiver(
		address.EncodeAddress(), uint64(sharedOutputAmount),
	)

	partialTx, err := a.sendOnchain(ctx, []Receiver{onchainReceiver})
	if err != nil {
		return "", err
	}

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(partialTx), true)
	if err != nil {
		return "", err
	}
	txid := ptx.UnsignedTx.TxHash().String()

	congestionTree, err := bitcointree.CraftCongestionTree(
		&wire.OutPoint{
			Hash:  ptx.UnsignedTx.TxHash(),
			Index: 0,
		},
		cosigners,
		aspPubkey,
		leaves,
		a.MinRelayFee,
		a.RoundLifetime,
		a.UnilateralExitDelay,
	)
	if err != nil {
		return "", err
	}

	sweepClosure := bitcointree.CSVSigClosure{
		Pubkey:  aspPubkey,
		Seconds: uint(a.RoundLifetime),
	}

	sweepTapLeaf, err := sweepClosure.Leaf()
	if err != nil {
		return "", err
	}

	sweepTapTree := txscript.AssembleTaprootScriptTree(*sweepTapLeaf)
	root := sweepTapTree.RootNode.TapHash()

	signer := bitcointree.NewTreeSignerSession(
		ephemeralKey,
		congestionTree,
		int64(a.MinRelayFee),
		root.CloneBytes(),
	)

	nonces, err := signer.GetNonces() // TODO send nonces to ASP
	if err != nil {
		return "", err
	}

	coordinator, err := bitcointree.NewTreeCoordinatorSession(
		congestionTree,
		int64(a.MinRelayFee),
		root.CloneBytes(),
		cosigners,
	)
	if err != nil {
		return "", err
	}

	if err := coordinator.AddNonce(ephemeralKey.PubKey(), nonces); err != nil {
		return "", err
	}

	aggregatedNonces, err := coordinator.AggregateNonces()
	if err != nil {
		return "", err
	}

	if err := signer.SetKeys(cosigners, aggregatedNonces); err != nil {
		return "", err
	}

	sigs, err := signer.Sign()
	if err != nil {
		return "", err
	}

	if err := coordinator.AddSig(ephemeralKey.PubKey(), sigs); err != nil {
		return "", err
	}

	signedTree, err := coordinator.SignTree()
	if err != nil {
		return "", err
	}

	if err := a.client.Onboard(
		ctx, partialTx, userPubkeyStr, signedTree,
	); err != nil {
		return "", err
	}

	return txid, nil
}

func (a *covenantlessArkClient) Balance(
	ctx context.Context, computeVtxoExpiration bool,
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

func (a *covenantlessArkClient) SendOnChain(
	ctx context.Context, receivers []Receiver,
) (string, error) {
	for _, receiver := range receivers {
		if !receiver.isOnchain() {
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
		if receiver.isOnchain() {
			return "", fmt.Errorf("invalid receiver address '%s': must be offchain", receiver.To())
		}
	}

	return a.sendOffchain(ctx, withExpiryCoinselect, receivers)
}

func (a *covenantlessArkClient) UnilateralRedeem(ctx context.Context) error {
	if a.wallet.IsLocked() {
		return fmt.Errorf("wallet is locked")
	}

	offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return err
	}

	vtxos := make([]client.Vtxo, 0)
	for _, offchainAddr := range offchainAddrs {
		spendableVtxos, _, err := a.getVtxos(ctx, offchainAddr, false)
		if err != nil {
			return err
		}
		vtxos = append(vtxos, spendableVtxos...)
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

	vtxos := make([]client.Vtxo, 0)
	for _, offchainAddr := range offchainAddrs {
		spendableVtxos, _, err := a.getVtxos(ctx, offchainAddr, withExpiryCoinselect)
		if err != nil {
			return "", err
		}
		vtxos = append(vtxos, spendableVtxos...)
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
		receivers = append(receivers, client.Output{
			Address: offchainAddr,
			Amount:  changeAmount,
		})
	}

	inputs := make([]client.VtxoKey, 0, len(selectedCoins))

	for _, coin := range selectedCoins {
		inputs = append(inputs, client.VtxoKey{
			Txid: coin.Txid,
			VOut: coin.VOut,
		})
	}

	paymentID, err := a.client.RegisterPayment(ctx, inputs)
	if err != nil {
		return "", err
	}

	if err := a.client.ClaimPayment(ctx, paymentID, receivers); err != nil {
		return "", err
	}

	poolTxID, err := a.handleRoundStream(
		ctx, paymentID, selectedCoins, receivers,
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

	for _, receiver := range receivers {
		isOnchain, _, _, err := utils.DecodeReceiverAddress(receiver.To())
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

	_, _, aspPubKey, err := common.DecodeAddress(offchainAddrs[0])
	if err != nil {
		return "", err
	}

	receiversOutput := make([]client.Output, 0)
	sumOfReceivers := uint64(0)

	for _, receiver := range receivers {
		_, _, aspKey, err := common.DecodeAddress(receiver.To())
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		if !bytes.Equal(
			aspPubKey.SerializeCompressed(), aspKey.SerializeCompressed(),
		) {
			return "", fmt.Errorf("invalid receiver address '%s': must be associated with the connected service provider", receiver)
		}

		if receiver.Amount() < DUST {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount(), DUST)
		}

		receiversOutput = append(receiversOutput, client.Output{
			Address: receiver.To(),
			Amount:  receiver.Amount(),
		})
		sumOfReceivers += receiver.Amount()
	}

	vtxos, _, err := a.getVtxos(ctx, offchainAddrs[0], withExpiryCoinselect)
	if err != nil {
		return "", err
	}
	selectedCoins, changeAmount, err := utils.CoinSelect(
		vtxos, sumOfReceivers, DUST, withExpiryCoinselect,
	)
	if err != nil {
		return "", err
	}

	if changeAmount > 0 {
		changeReceiver := client.Output{
			Address: offchainAddrs[0],
			Amount:  changeAmount,
		}
		receiversOutput = append(receiversOutput, changeReceiver)
	}

	inputs := make([]client.VtxoKey, 0, len(selectedCoins))

	for _, coin := range selectedCoins {
		inputs = append(inputs, coin.VtxoKey)
	}

	redeemTx, unconditionalForfeitTxs, err := a.client.CreatePayment(
		ctx, inputs, receiversOutput)
	if err != nil {
		return "", err
	}

	// TODO verify the redeem tx signature

	signedUnconditionalForfeitTxs := make([]string, 0, len(unconditionalForfeitTxs))
	for _, tx := range unconditionalForfeitTxs {
		signedForfeitTx, err := a.wallet.SignTransaction(ctx, a.explorer, tx)
		if err != nil {
			return "", err
		}

		signedUnconditionalForfeitTxs = append(signedUnconditionalForfeitTxs, signedForfeitTx)
	}

	signedRedeemTx, err := a.wallet.SignTransaction(ctx, a.explorer, redeemTx)
	if err != nil {
		return "", err
	}

	if err = a.client.CompletePayment(
		ctx, signedRedeemTx, signedUnconditionalForfeitTxs,
	); err != nil {
		return "", err
	}

	return signedRedeemTx, nil
}

func (a *covenantlessArkClient) ClaimAsync(
	ctx context.Context,
) (string, error) {
	myselfOffchain, _, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", err
	}

	_, pendingVtxos, err := a.getVtxos(ctx, myselfOffchain, false)
	if err != nil {
		return "", err
	}

	var pendingBalance uint64
	for _, vtxo := range pendingVtxos {
		pendingBalance += vtxo.Amount
	}
	if pendingBalance == 0 {
		return "", nil
	}

	receiver := client.Output{
		Address: myselfOffchain,
		Amount:  pendingBalance,
	}
	return a.selfTransferAllPendingPayments(ctx, pendingVtxos, receiver)
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
		if receiver.Amount() < DUST {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount(), DUST)
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

	utxos, delayedUtxos, change, err := a.coinSelectOnchain(
		ctx, targetAmount, nil,
	)
	if err != nil {
		return "", err
	}

	if err := a.addInputs(ctx, updater, utxos, delayedUtxos, &netParams); err != nil {
		return "", err
	}

	if change > 0 {
		_, changeAddr, err := a.wallet.NewAddress(ctx, true)
		if err != nil {
			return "", err
		}
		addr, _ := btcutil.DecodeAddress(changeAddr, &netParams)

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
		selected, delayedSelected, newChange, err := a.coinSelectOnchain(
			ctx, feeAmount-change, append(utxos, delayedUtxos...),
		)
		if err != nil {
			return "", err
		}

		if err := a.addInputs(ctx, updater, selected, delayedSelected, &netParams); err != nil {
			return "", err
		}

		if newChange > 0 {
			_, changeAddr, err := a.wallet.NewAddress(ctx, true)
			if err != nil {
				return "", err
			}
			addr, _ := btcutil.DecodeAddress(changeAddr, &netParams)

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

	receiversOutput := make([]client.Output, 0)
	sumOfReceivers := uint64(0)

	for _, receiver := range receivers {
		_, _, aspKey, err := common.DecodeAddress(receiver.To())
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		if !bytes.Equal(
			aspPubKey.SerializeCompressed(), aspKey.SerializeCompressed(),
		) {
			return "", fmt.Errorf("invalid receiver address '%s': must be associated with the connected service provider", receiver.To())
		}

		if receiver.Amount() < DUST {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount(), DUST)
		}

		receiversOutput = append(receiversOutput, client.Output{
			Address: receiver.To(),
			Amount:  receiver.Amount(),
		})
		sumOfReceivers += receiver.Amount()
	}

	vtxos := make([]client.Vtxo, 0)
	for _, offchainAddr := range offchainAddrs {
		spendableVtxos, _, err := a.getVtxos(ctx, offchainAddr, withExpiryCoinselect)
		if err != nil {
			return "", err
		}
		vtxos = append(vtxos, spendableVtxos...)
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
		changeReceiver := client.Output{
			Address: offchainAddr,
			Amount:  changeAmount,
		}
		receiversOutput = append(receiversOutput, changeReceiver)
	}

	inputs := make([]client.VtxoKey, 0, len(selectedCoins))
	for _, coin := range selectedCoins {
		inputs = append(inputs, client.VtxoKey{
			Txid: coin.Txid,
			VOut: coin.VOut,
		})
	}

	paymentID, err := a.client.RegisterPayment(
		ctx, inputs,
	)
	if err != nil {
		return "", err
	}

	if err := a.client.ClaimPayment(
		ctx, paymentID, receiversOutput,
	); err != nil {
		return "", err
	}

	log.Infof("payment registered with id: %s", paymentID)

	poolTxID, err := a.handleRoundStream(
		ctx, paymentID, selectedCoins, receiversOutput,
	)
	if err != nil {
		return "", err
	}

	return poolTxID, nil
}

func (a *covenantlessArkClient) addInputs(
	ctx context.Context, updater *psbt.Updater,
	utxos, delayedUtxos []explorer.Utxo, net *chaincfg.Params,
) error {
	offchainAddr, onchainAddr, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return err
	}
	addr, _ := btcutil.DecodeAddress(onchainAddr, net)

	changeScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}

	for _, utxo := range utxos {
		previousHash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return err
		}

		updater.Upsbt.UnsignedTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *previousHash,
				Index: utxo.Vout,
			},
		})

		updater.Upsbt.Inputs = append(updater.Upsbt.Inputs, psbt.PInput{})

		if err := updater.AddInWitnessUtxo(
			&wire.TxOut{
				Value:    int64(utxo.Amount),
				PkScript: changeScript,
			},
			len(updater.Upsbt.UnsignedTx.TxIn)-1,
		); err != nil {
			return err
		}
	}

	if len(delayedUtxos) > 0 {
		_, userPubkey, aspPubkey, _ := common.DecodeAddress(offchainAddr)

		vtxoTapKey, leafProof, err := bitcointree.ComputeVtxoTaprootScript(
			userPubkey, aspPubkey, uint(a.UnilateralExitDelay),
		)
		if err != nil {
			return err
		}

		p2tr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(vtxoTapKey), net)
		if err != nil {
			return err
		}

		script, err := txscript.PayToAddrScript(p2tr)
		if err != nil {
			return err
		}

		for _, utxo := range delayedUtxos {
			previousHash, err := chainhash.NewHashFromStr(utxo.Txid)
			if err != nil {
				return err
			}

			if err := a.addVtxoInput(
				updater,
				&wire.OutPoint{
					Hash:  *previousHash,
					Index: utxo.Vout,
				},
				uint(a.UnilateralExitDelay),
				leafProof,
			); err != nil {
				return err
			}

			if err := updater.AddInWitnessUtxo(
				&wire.TxOut{
					Value:    int64(utxo.Amount),
					PkScript: script,
				},
				len(updater.Upsbt.Inputs)-1,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *covenantlessArkClient) addVtxoInput(
	updater *psbt.Updater, inputArgs *wire.OutPoint, exitDelay uint,
	tapLeafProof *txscript.TapscriptProof,
) error {
	sequence, err := common.BIP68EncodeAsNumber(exitDelay)
	if err != nil {
		return nil
	}

	nextInputIndex := len(updater.Upsbt.Inputs)
	updater.Upsbt.UnsignedTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *inputArgs,
		Sequence:         sequence,
	})
	updater.Upsbt.Inputs = append(updater.Upsbt.Inputs, psbt.PInput{})

	controlBlock := tapLeafProof.ToControlBlock(bitcointree.UnspendableKey())
	controlBlockBytes, err := controlBlock.ToBytes()
	if err != nil {
		return err
	}

	updater.Upsbt.Inputs[nextInputIndex].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: controlBlockBytes,
			Script:       tapLeafProof.Script,
			LeafVersion:  tapLeafProof.LeafVersion,
		},
	}

	return nil
}

func (a *covenantlessArkClient) handleRoundStream(
	ctx context.Context,
	paymentID string, vtxosToSign []client.Vtxo, receivers []client.Output,
) (string, error) {
	eventsCh, err := a.client.GetEventStream(ctx, paymentID)
	if err != nil {
		return "", err
	}

	var pingStop func()
	for pingStop == nil {
		pingStop = a.ping(ctx, paymentID)
	}

	defer pingStop()

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

				signedForfeitTxs, err := a.handleRoundFinalization(
					ctx, event.(client.RoundFinalizationEvent), vtxosToSign, receivers,
				)
				if err != nil {
					return "", err
				}

				if len(signedForfeitTxs) <= 0 {
					log.Info("no forfeit txs to sign, waiting for the next round")
					continue
				}

				log.Info("finalizing payment... ")
				if err := a.client.FinalizePayment(ctx, signedForfeitTxs); err != nil {
					return "", err
				}

				log.Info("done.")
				log.Info("waiting for round finalization...")
			}
		}
	}
}

func (a *covenantlessArkClient) handleRoundFinalization(
	ctx context.Context, event client.RoundFinalizationEvent,
	vtxos []client.Vtxo, receivers []client.Output,
) ([]string, error) {
	if err := a.validateCongestionTree(event, receivers); err != nil {
		return nil, fmt.Errorf("failed to verify congestion tree: %s", err)
	}

	return a.loopAndSign(
		ctx, event.ForfeitTxs, vtxos, event.Connectors,
	)
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
			event.Tree, poolTx, a.StoreData.AspPubkey, a.RoundLifetime, int64(a.MinRelayFee),
		); err != nil {
			return err
		}
	}

	// if err := common.ValidateConnectors(poolTx, event.Connectors); err != nil {
	// 	return err
	// }

	if err := a.validateReceivers(
		ptx, receivers, event.Tree, a.StoreData.AspPubkey,
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
	aspPubkey *secp256k1.PublicKey,
) error {
	for _, receiver := range receivers {
		isOnChain, onchainScript, userPubkey, err := utils.DecodeReceiverAddress(
			receiver.Address,
		)
		if err != nil {
			return err
		}

		if isOnChain {
			if err := a.validateOnChainReceiver(ptx, receiver, onchainScript); err != nil {
				return err
			}
		} else {
			if err := a.validateOffChainReceiver(
				congestionTree, receiver, userPubkey, aspPubkey,
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
	userPubkey, aspPubkey *secp256k1.PublicKey,
) error {
	found := false
	outputTapKey, _, err := bitcointree.ComputeVtxoTaprootScript(
		userPubkey, aspPubkey, uint(a.UnilateralExitDelay),
	)
	if err != nil {
		return err
	}

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

			if bytes.Equal(
				output.PkScript[2:], schnorr.SerializePubKey(outputTapKey),
			) {
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

func (a *covenantlessArkClient) loopAndSign(
	ctx context.Context,
	forfeitTxs []string, vtxosToSign []client.Vtxo, connectors []string,
) ([]string, error) {
	signedForfeits := make([]string, 0)

	connectorsTxids := make([]string, 0, len(connectors))
	for _, connector := range connectors {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(connector), true)
		if err != nil {
			return nil, err
		}
		txid := ptx.UnsignedTx.TxHash().String()
		connectorsTxids = append(connectorsTxids, txid)
	}

	for _, forfeitTx := range forfeitTxs {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(forfeitTx), true)
		if err != nil {
			return nil, err
		}

		for _, input := range ptx.UnsignedTx.TxIn {
			inputTxid := input.PreviousOutPoint.Hash.String()

			for _, coin := range vtxosToSign {
				// check if it contains one of the input to sign
				if inputTxid == coin.Txid {
					// verify that the connector is in the connectors list
					connectorTxid := ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String()
					connectorFound := false
					for _, txid := range connectorsTxids {
						if txid == connectorTxid {
							connectorFound = true
							break
						}
					}

					if !connectorFound {
						return nil, fmt.Errorf("connector txid %s not found in the connectors list", connectorTxid)
					}

					signedForfeitTx, err := a.wallet.SignTransaction(ctx, a.explorer, forfeitTx)
					if err != nil {
						return nil, err
					}

					signedForfeits = append(signedForfeits, signedForfeitTx)
				}
			}
		}
	}

	return signedForfeits, nil
}

func (a *covenantlessArkClient) coinSelectOnchain(
	ctx context.Context, targetAmount uint64, exclude []explorer.Utxo,
) ([]explorer.Utxo, []explorer.Utxo, uint64, error) {
	offchainAddrs, onchainAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, nil, 0, err
	}

	net := utils.ToBitcoinNetwork(a.Network)

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

		vtxoTapKey, _, err := bitcointree.ComputeVtxoTaprootScript(
			userPubkey, aspPubkey, uint(a.UnilateralExitDelay),
		)
		if err != nil {
			return nil, nil, 0, err
		}
		p2tr, err := btcutil.NewAddressTaproot(
			schnorr.SerializePubKey(vtxoTapKey), &net,
		)
		if err != nil {
			return nil, nil, 0, err
		}

		addr := p2tr.EncodeAddress()

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

func (a *covenantlessArkClient) getRedeemBranches(
	ctx context.Context, vtxos []client.Vtxo,
) (map[string]*redemption.CovenantlessRedeemBranch, error) {
	congestionTrees := make(map[string]tree.CongestionTree, 0)
	redeemBranches := make(map[string]*redemption.CovenantlessRedeemBranch, 0)

	for i := range vtxos {
		vtxo := vtxos[i]
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

// TODO: return pending balance. ATM returns only the balance by expiration of the vtxos built from rounds
func (a *covenantlessArkClient) getOffchainBalance(
	ctx context.Context, addr string, computeVtxoExpiration bool,
) (uint64, map[int64]uint64, error) {
	amountByExpiration := make(map[int64]uint64, 0)

	vtxos, _, err := a.getVtxos(ctx, addr, computeVtxoExpiration)
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

func (a *covenantlessArkClient) getVtxos(
	ctx context.Context, addr string, computeVtxoExpiration bool,
) ([]client.Vtxo, []client.Vtxo, error) {
	vtxos, _, err := a.client.ListVtxos(ctx, addr)
	if err != nil {
		return nil, nil, err
	}

	pendingVtxos := make([]client.Vtxo, 0)
	spendableVtxos := make([]client.Vtxo, 0)
	for _, vtxo := range vtxos {
		if vtxo.Pending {
			pendingVtxos = append(pendingVtxos, vtxo)
			continue
		}
		spendableVtxos = append(spendableVtxos, vtxo)
	}

	if !computeVtxoExpiration {
		return spendableVtxos, pendingVtxos, nil
	}

	redeemBranches, err := a.getRedeemBranches(ctx, spendableVtxos)
	if err != nil {
		return nil, nil, err
	}

	for vtxoTxid, branch := range redeemBranches {
		expiration, err := branch.ExpiresAt()
		if err != nil {
			return nil, nil, err
		}

		for i, vtxo := range spendableVtxos {
			if vtxo.Txid == vtxoTxid {
				vtxos[i].ExpiresAt = expiration
				break
			}
		}
	}

	return spendableVtxos, pendingVtxos, nil
}

func (a *covenantlessArkClient) selfTransferAllPendingPayments(
	ctx context.Context, pendingVtxos []client.Vtxo, myself client.Output,
) (string, error) {
	inputs := make([]client.VtxoKey, 0, len(pendingVtxos))

	for _, coin := range pendingVtxos {
		inputs = append(inputs, coin.VtxoKey)
	}

	outputs := []client.Output{myself}

	paymentID, err := a.client.RegisterPayment(ctx, inputs)
	if err != nil {
		return "", err
	}

	if err := a.client.ClaimPayment(ctx, paymentID, outputs); err != nil {
		return "", err
	}

	roundTxid, err := a.handleRoundStream(
		ctx, paymentID, pendingVtxos, outputs,
	)
	if err != nil {
		return "", err
	}

	return roundTxid, nil
}
