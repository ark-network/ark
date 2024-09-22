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
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/redemption"
	"github.com/ark-network/ark/pkg/client-sdk/store"
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

	explorerSvc, err := getExplorer(data.ExplorerURL, data.Network.Name)
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

	explorerSvc, err := getExplorer(data.ExplorerURL, data.Network.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to setup explorer: %s", err)
	}

	return &covenantlessArkClient{
		&arkClient{data, walletSvc, storeSvc, explorerSvc, clientSvc},
	}, nil
}

func (a *covenantlessArkClient) ListVtxos(
	ctx context.Context,
) (spendableVtxos, spentVtxos []client.Vtxo, err error) {
	offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return
	}

	_, pubkey, _, err := common.DecodeAddress(offchainAddrs[0])
	if err != nil {
		return
	}

	myPubkey := schnorr.SerializePubKey(pubkey)

	// The ASP returns the vtxos sent to others via async payments as spendable
	// because they are actually revertable. Since we do not provide any revert
	// feature, we want to ignore them.
	// To understand if the output of a redeem tx is sent or received we look at
	// the inputs and check if they are owned by us.
	// The auxiliary variables below are used to make these checks in an
	// efficient way.
	for _, addr := range offchainAddrs {
		spendable, spent, err := a.client.ListVtxos(ctx, addr)
		if err != nil {
			return nil, nil, err
		}
		for _, v := range spendable {
			if !v.Pending {
				spendableVtxos = append(spendableVtxos, v)
				continue
			}
			script, err := bitcointree.ParseVtxoScript(v.Descriptor)
			if err != nil {
				return nil, nil, err
			}

			reversibleVtxo, ok := script.(*bitcointree.ReversibleVtxoScript)
			if !ok {
				spendableVtxos = append(spendableVtxos, v)
				continue
			}

			if !bytes.Equal(schnorr.SerializePubKey(reversibleVtxo.Sender), myPubkey) {
				spendableVtxos = append(spendableVtxos, v)
			}
		}
		for _, v := range spent {
			script, err := bitcointree.ParseVtxoScript(v.Descriptor)
			if err != nil {
				return nil, nil, err
			}

			reversibleVtxo, ok := script.(*bitcointree.ReversibleVtxoScript)
			if !ok {
				spentVtxos = append(spentVtxos, v)
				continue
			}
			if !bytes.Equal(schnorr.SerializePubKey(reversibleVtxo.Sender), myPubkey) {
				spentVtxos = append(spentVtxos, v)
			}
		}
	}

	return
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
		}(offchainAddr)

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

		go getDelayedBalance(boardingAddr)
		go getDelayedBalance(redeemAddr)
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

	vtxos := make([]client.Vtxo, 0)
	for _, offchainAddr := range offchainAddrs {
		spendableVtxos, _, err := a.getVtxos(ctx, offchainAddr, withExpiryCoinselect)
		if err != nil {
			return "", err
		}
		vtxos = append(vtxos, spendableVtxos...)
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

		desc, err := a.offchainAddressToDefaultVtxoDescriptor(offchainAddr)
		if err != nil {
			return "", err
		}

		receivers = append(receivers, client.Output{
			Descriptor: desc,
			Amount:     changeAmount,
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

	roundEphemeralKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return "", err
	}

	paymentID, err := a.client.RegisterPayment(
		ctx,
		inputs,
		hex.EncodeToString(roundEphemeralKey.PubKey().SerializeCompressed()),
	)
	if err != nil {
		return "", err
	}

	if err := a.client.ClaimPayment(ctx, paymentID, receivers); err != nil {
		return "", err
	}

	poolTxID, err := a.handleRoundStream(
		ctx, paymentID, selectedCoins, nil, "", receivers, roundEphemeralKey,
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

		if receiver.Amount() < a.Dust {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount(), a.Dust)
		}

		isSelfTransfer := offchainAddrs[0] == receiver.To()

		var desc string

		// reversible vtxo does not make sense for self transfer
		// if the receiver is the same as the sender, handle the output like the change
		if !isSelfTransfer {
			desc, err = a.offchainAddressToReversibleVtxoDescriptor(offchainAddrs[0], receiver.To())
			if err != nil {
				return "", err
			}
		} else {
			desc, err = a.offchainAddressToDefaultVtxoDescriptor(receiver.To())
			if err != nil {
				return "", err
			}
		}

		receiversOutput = append(receiversOutput, client.Output{
			Descriptor: desc,
			Amount:     receiver.Amount(),
		})
		sumOfReceivers += receiver.Amount()
	}

	vtxos, _, err := a.getVtxos(ctx, offchainAddrs[0], withExpiryCoinselect)
	if err != nil {
		return "", err
	}
	selectedCoins, changeAmount, err := utils.CoinSelect(
		vtxos, sumOfReceivers, a.Dust, withExpiryCoinselect,
	)
	if err != nil {
		return "", err
	}

	if changeAmount > 0 {
		changeDesc, err := a.offchainAddressToDefaultVtxoDescriptor(offchainAddrs[0])
		if err != nil {
			return "", err
		}

		changeReceiver := client.Output{
			Descriptor: changeDesc,
			Amount:     changeAmount,
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

	redeemTx, unconditionalForfeitTxs, err := a.client.CreatePayment(
		ctx, inputs, receiversOutput)
	if err != nil {
		return "", err
	}

	// TODO verify the redeem tx signature

	signedRedeemTx, err := a.wallet.SignTransaction(ctx, a.explorer, redeemTx)
	if err != nil {
		return "", err
	}

	if err = a.client.CompletePayment(
		ctx, signedRedeemTx, unconditionalForfeitTxs,
	); err != nil {
		return "", err
	}

	return signedRedeemTx, nil
}

func (a *covenantlessArkClient) Claim(ctx context.Context) (string, error) {
	myselfOffchain, _, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", err
	}

	_, pendingVtxos, err := a.getVtxos(ctx, myselfOffchain, false)
	if err != nil {
		return "", err
	}

	_, mypubkey, _, err := common.DecodeAddress(myselfOffchain)
	if err != nil {
		return "", err
	}

	boardingUtxos, err := a.getClaimableBoardingUtxos(ctx)
	if err != nil {
		return "", err
	}

	var pendingBalance uint64
	for _, vtxo := range pendingVtxos {
		pendingBalance += vtxo.Amount
	}
	for _, vtxo := range boardingUtxos {
		pendingBalance += vtxo.Amount
	}
	if pendingBalance == 0 {
		return "", nil
	}

	desc, err := a.offchainAddressToDefaultVtxoDescriptor(myselfOffchain)
	if err != nil {
		return "", err
	}

	receiver := client.Output{
		Descriptor: desc,
		Amount:     pendingBalance,
	}

	return a.selfTransferAllPendingPayments(
		ctx,
		pendingVtxos,
		boardingUtxos,
		receiver,
		hex.EncodeToString(mypubkey.SerializeCompressed()),
	)
}

func (a *covenantlessArkClient) GetTransactionHistory(ctx context.Context) ([]Transaction, error) {
	spendableVtxos, spentVtxos, err := a.ListVtxos(ctx)
	if err != nil {
		return nil, err
	}

	config, err := a.store.GetData(ctx)
	if err != nil {
		return nil, err
	}

	boardingTxs := a.getBoardingTxs(ctx)

	return vtxosToTxsCovenantless(config.RoundLifetime, spendableVtxos, spentVtxos, boardingTxs)
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

		if receiver.Amount() < a.Dust {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount(), a.Dust)
		}

		desc, err := a.offchainAddressToDefaultVtxoDescriptor(receiver.To())
		if err != nil {
			return "", err
		}

		receiversOutput = append(receiversOutput, client.Output{
			Descriptor: desc,
			Amount:     receiver.Amount(),
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

		desc, err := a.offchainAddressToDefaultVtxoDescriptor(offchainAddr)
		if err != nil {
			return "", err
		}

		changeReceiver := client.Output{
			Descriptor: desc,
			Amount:     changeAmount,
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

	roundEphemeralKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return "", err
	}

	paymentID, err := a.client.RegisterPayment(
		ctx, inputs, hex.EncodeToString(roundEphemeralKey.PubKey().SerializeCompressed()),
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
		ctx, paymentID, selectedCoins, nil, "", receiversOutput, roundEphemeralKey,
	)
	if err != nil {
		return "", err
	}

	return poolTxID, nil
}

func (a *covenantlessArkClient) addInputs(
	ctx context.Context,
	updater *psbt.Updater,
	utxos []explorer.Utxo,
) error {
	// TODO works only with single-key wallet
	offchain, _, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return err
	}

	_, userPubkey, aspPubkey, err := common.DecodeAddress(offchain)
	if err != nil {
		return err
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
				Index: utxo.Vout,
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
	vtxosToSign []client.Vtxo,
	boardingUtxos []explorer.Utxo,
	boardingDescriptor string,
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
				if err := a.client.FinalizePayment(ctx, signedForfeitTxs, signedRoundTx); err != nil {
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

	err = a.arkClient.client.SendTreeNonces(ctx, event.ID, myPubKey, nonces)

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

	if err := a.arkClient.client.SendTreeSignatures(
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
	vtxos []client.Vtxo,
	boardingUtxos []explorer.Utxo,
	boardingDescriptor string,
	receivers []client.Output,
) ([]string, string, error) {
	if err := a.validateCongestionTree(event, receivers); err != nil {
		return nil, "", fmt.Errorf("failed to verify congestion tree: %s", err)
	}

	offchainAddr, _, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return nil, "", err
	}

	_, myPubkey, _, err := common.DecodeAddress(offchainAddr)
	if err != nil {
		return nil, "", err
	}

	var forfeits []string

	if len(vtxos) > 0 {
		signedForfeits, err := a.createAndSignForfeits(
			ctx, vtxos, event.Connectors, event.MinRelayFeeRate, myPubkey,
		)
		if err != nil {
			return nil, "", err
		}

		forfeits = signedForfeits
	}

	if len(boardingUtxos) > 0 {
		boardingVtxoScript, err := bitcointree.ParseVtxoScript(boardingDescriptor)
		if err != nil {
			return nil, "", err
		}

		roundPtx, err := psbt.NewFromRawBytes(strings.NewReader(event.Tx), true)
		if err != nil {
			return nil, "", err
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

			for _, boardingUtxo := range boardingUtxos {
				if boardingUtxo.Txid == previousOutpoint.Hash.String() && boardingUtxo.Vout == previousOutpoint.Index {
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

	return forfeits, "", nil
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
			event.Tree, poolTx, a.StoreData.AspPubkey, a.RoundLifetime,
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

	receiverVtxoScript, err := bitcointree.ParseVtxoScript(receiver.Descriptor)
	if err != nil {
		return err
	}

	outputTapKey, _, err := receiverVtxoScript.TapTree()
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

func (a *covenantlessArkClient) createAndSignForfeits(
	ctx context.Context,
	vtxosToSign []client.Vtxo,
	connectors []string,
	feeRate chainfee.SatPerKVByte,
	myPubkey *secp256k1.PublicKey,
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

		forfeitClosure := &bitcointree.MultisigClosure{
			Pubkey:    myPubkey,
			AspPubkey: a.AspPubkey,
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
				connectorPset, vtxoInput, vtxo.Amount, a.Dust, feeAmount, vtxoOutputScript, a.ForfeitAddress,
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
	ctx context.Context, targetAmount uint64, exclude []explorer.Utxo,
) ([]explorer.Utxo, uint64, error) {
	offchainAddrs, boardingAddrs, redemptionAddrs, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, 0, err
	}

	_, myPubkey, _, err := common.DecodeAddress(offchainAddrs[0])
	if err != nil {
		return nil, 0, err
	}

	myPubkeyStr := hex.EncodeToString(schnorr.SerializePubKey(myPubkey))
	descriptorStr := strings.ReplaceAll(
		a.BoardingDescriptorTemplate, "USER", myPubkeyStr,
	)

	boardingScript, err := bitcointree.ParseVtxoScript(descriptorStr)
	if err != nil {
		return nil, 0, err
	}

	var boardingTimeout uint

	if defaultVtxo, ok := boardingScript.(*bitcointree.DefaultVtxoScript); ok {
		boardingTimeout = defaultVtxo.ExitDelay
	} else {
		return nil, 0, fmt.Errorf("unsupported boarding descriptor: %s", descriptorStr)
	}

	now := time.Now()

	fetchedUtxos := make([]explorer.Utxo, 0)
	for _, addr := range boardingAddrs {
		utxos, err := a.explorer.GetUtxos(addr)
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
		utxos, err := a.explorer.GetUtxos(addr)
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

// TODO (@louisinger): return pending balance in dedicated map.
// Currently, the returned balance is calculated from both spendable and
// pending vtxos.
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

func (a *covenantlessArkClient) getAllBoardingUtxos(ctx context.Context) ([]explorer.Utxo, error) {
	_, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	utxos := []explorer.Utxo{}
	for _, addr := range boardingAddrs {
		txs, err := a.explorer.GetTxs(addr)
		if err != nil {
			continue
		}
		for _, tx := range txs {
			for i, vout := range tx.Vout {
				if vout.Address == addr {
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

func (a *covenantlessArkClient) getClaimableBoardingUtxos(ctx context.Context) ([]explorer.Utxo, error) {
	offchainAddrs, boardingAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	_, myPubkey, _, err := common.DecodeAddress(offchainAddrs[0])
	if err != nil {
		return nil, err
	}

	myPubkeyStr := hex.EncodeToString(schnorr.SerializePubKey(myPubkey))
	descriptorStr := strings.ReplaceAll(
		a.BoardingDescriptorTemplate, "USER", myPubkeyStr,
	)

	boardingScript, err := bitcointree.ParseVtxoScript(descriptorStr)
	if err != nil {
		return nil, err
	}

	var boardingTimeout uint

	if defaultVtxo, ok := boardingScript.(*bitcointree.DefaultVtxoScript); ok {
		boardingTimeout = defaultVtxo.ExitDelay
	} else {
		return nil, fmt.Errorf("unsupported boarding descriptor: %s", descriptorStr)
	}

	claimable := make([]explorer.Utxo, 0)
	now := time.Now()

	for _, addr := range boardingAddrs {
		boardingUtxos, err := a.explorer.GetUtxos(addr)
		if err != nil {
			return nil, err
		}

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

func (a *covenantlessArkClient) getVtxos(
	ctx context.Context, _ string, computeVtxoExpiration bool,
) ([]client.Vtxo, []client.Vtxo, error) {
	spendableVtxos, _, err := a.ListVtxos(ctx)
	if err != nil {
		return nil, nil, err
	}

	pendingVtxos := make([]client.Vtxo, 0)
	for _, vtxo := range spendableVtxos {
		if vtxo.Pending {
			pendingVtxos = append(pendingVtxos, vtxo)
		}
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
				spendableVtxos[i].ExpiresAt = expiration
				break
			}
		}
	}

	return spendableVtxos, pendingVtxos, nil
}

func (a *covenantlessArkClient) selfTransferAllPendingPayments(
	ctx context.Context, pendingVtxos []client.Vtxo, boardingUtxos []explorer.Utxo, myself client.Output, mypubkey string,
) (string, error) {
	inputs := make([]client.Input, 0, len(pendingVtxos)+len(boardingUtxos))

	boardingDescriptor := strings.ReplaceAll(
		a.BoardingDescriptorTemplate, "USER", mypubkey[2:],
	)

	for _, coin := range pendingVtxos {
		inputs = append(inputs, client.Input{
			Outpoint: client.Outpoint{
				Txid: coin.Txid,
				VOut: coin.VOut,
			},
			Descriptor: coin.Descriptor,
		})
	}

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

	roundEphemeralKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return "", err
	}

	paymentID, err := a.client.RegisterPayment(
		ctx,
		inputs,
		hex.EncodeToString(roundEphemeralKey.PubKey().SerializeCompressed()),
	)
	if err != nil {
		return "", err
	}

	if err := a.client.ClaimPayment(ctx, paymentID, outputs); err != nil {
		return "", err
	}

	roundTxid, err := a.handleRoundStream(
		ctx, paymentID, pendingVtxos, boardingUtxos, boardingDescriptor, outputs, roundEphemeralKey,
	)
	if err != nil {
		return "", err
	}

	return roundTxid, nil
}

func (a *covenantlessArkClient) offchainAddressToReversibleVtxoDescriptor(myaddr string, receiveraddr string) (string, error) {
	_, receiverPubkey, aspPubkey, err := common.DecodeAddress(receiveraddr)
	if err != nil {
		return "", err
	}

	_, userPubKey, _, err := common.DecodeAddress(myaddr)
	if err != nil {
		return "", err
	}

	vtxoScript := bitcointree.ReversibleVtxoScript{
		Owner:     receiverPubkey,
		Sender:    userPubKey,
		Asp:       aspPubkey,
		ExitDelay: uint(a.UnilateralExitDelay),
	}

	return vtxoScript.ToDescriptor(), nil
}

func (a *covenantlessArkClient) offchainAddressToDefaultVtxoDescriptor(addr string) (string, error) {
	_, userPubKey, aspPubkey, err := common.DecodeAddress(addr)
	if err != nil {
		return "", err
	}

	vtxoScript := bitcointree.DefaultVtxoScript{
		Owner:     userPubKey,
		Asp:       aspPubkey,
		ExitDelay: uint(a.UnilateralExitDelay),
	}

	return vtxoScript.ToDescriptor(), nil
}

func (a *covenantlessArkClient) getBoardingTxs(ctx context.Context) (transactions []Transaction) {
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
		transactions = append(transactions, Transaction{
			BoardingTxid: u.Txid,
			Amount:       u.Amount,
			Type:         TxReceived,
			IsPending:    pending,
			CreatedAt:    u.CreatedAt,
		})
	}
	return
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
	roundLifetime int64, spendable, spent []client.Vtxo, boardingTxs []Transaction,
) ([]Transaction, error) {
	transactions := make([]Transaction, 0)
	unconfirmedBoardingTxs := make([]Transaction, 0)
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
		// ignore not pending
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
		txType := TxReceived
		if amount < 0 {
			txType = TxSent
		}

		// get redeem txid
		redeemTxid := ""
		if len(v.RedeemTx) > 0 {
			txid, err := getRedeemTxidCovenantless(v.RedeemTx)
			if err != nil {
				return nil, err
			}
			redeemTxid = txid
		}
		// add transaction
		transactions = append(transactions, Transaction{
			RoundTxid:       v.RoundTxid,
			RedeemTxid:      redeemTxid,
			Amount:          uint64(math.Abs(float64(amount))),
			Type:            txType,
			IsPending:       (v.Pending && len(v.SpentBy) == 0),
			IsPendingChange: v.PendingChange,
			CreatedAt:       getCreatedAtFromExpiry(roundLifetime, *v.ExpiresAt),
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

func getRedeemTxidCovenantless(redeemTx string) (string, error) {
	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(redeemTx), true)
	if err != nil {
		return "", fmt.Errorf("failed to parse redeem tx: %s", err)
	}

	return redeemPtx.UnsignedTx.TxID(), nil
}
