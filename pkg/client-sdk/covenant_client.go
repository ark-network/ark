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
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils/redemption"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
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

func (r liquidReceiver) isOnchain() bool {
	_, err := address.ToOutputScript(r.to)
	return err == nil
}

type covenantArkClient struct {
	*arkClient
}

func NewCovenantClient(storeSvc store.ConfigStore) (ArkClient, error) {
	data, err := storeSvc.GetData(context.Background())
	if err != nil {
		return nil, err
	}
	if data != nil {
		return nil, ErrAlreadyInitialized
	}

	return &covenantArkClient{&arkClient{store: storeSvc}}, nil
}

func LoadCovenantClient(storeSvc store.ConfigStore) (ArkClient, error) {
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

	return &covenantArkClient{
		&arkClient{data, walletSvc, storeSvc, explorerSvc, clientSvc},
	}, nil
}

func LoadCovenantClientWithWallet(
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

	return &covenantArkClient{
		&arkClient{data, walletSvc, storeSvc, explorerSvc, clientSvc},
	}, nil
}

func (a *covenantArkClient) Onboard(
	ctx context.Context, amount uint64,
) (string, error) {
	if amount <= 0 {
		return "", fmt.Errorf("invalid amount to onboard %d", amount)
	}

	offchainAddr, _, err := a.wallet.NewAddress(ctx, false)
	if err != nil {
		return "", err
	}

	net := utils.ToElementsNetwork(a.Network)
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

	onchainReceiver := NewLiquidReceiver(addr, sharedOutputAmount)

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

	if err := a.client.Onboard(
		ctx, pset, userPubkeyStr, congestionTree,
	); err != nil {
		return "", err
	}

	return txid, nil
}

func (a *covenantArkClient) Balance(
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

func (a *covenantArkClient) SendOnChain(
	ctx context.Context, receivers []Receiver,
) (string, error) {
	for _, receiver := range receivers {
		if !receiver.isOnchain() {
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
		if receiver.isOnchain() {
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
		fetchedVtxos, _, err := a.client.ListVtxos(ctx, offchainAddr)
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

	vtxos := make([]client.Vtxo, 0)
	for _, offchainAddr := range offchainAddrs {
		spendableVtxos, err := a.getVtxos(ctx, offchainAddr, withExpiryCoinselect)
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
		if receiver.Amount() < DUST {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount(), DUST)
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
		spendableVtxos, err := a.getVtxos(ctx, offchainAddr, withExpiryCoinselect)
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

func (a *covenantArkClient) addInputs(
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
			if err := a.addVtxoInput(
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

func (a *covenantArkClient) addVtxoInput(
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

func (a *covenantArkClient) handleRoundStream(
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

func (a *covenantArkClient) handleRoundFinalization(
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
			event.Tree, poolTx, a.StoreData.AspPubkey, a.RoundLifetime,
		); err != nil {
			return err
		}
	}

	if err := common.ValidateConnectors(poolTx, connectors); err != nil {
		return err
	}

	if err := a.validateReceivers(
		ptx, receivers, event.Tree, a.StoreData.AspPubkey,
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
	userPubkey, aspPubkey *secp256k1.PublicKey,
) error {
	found := false
	net := utils.ToElementsNetwork(a.Network)
	outputTapKey, _, _, _, err := tree.ComputeVtxoTaprootScript(
		userPubkey, aspPubkey, uint(a.UnilateralExitDelay), net,
	)
	if err != nil {
		return err
	}

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
			if bytes.Equal(output.Script[2:], schnorr.SerializePubKey(outputTapKey)) {
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

func (a *covenantArkClient) loopAndSign(
	ctx context.Context,
	forfeitTxs []string, vtxosToSign []client.Vtxo, connectors []string,
) ([]string, error) {
	signedForfeits := make([]string, 0)

	connectorsTxids := make([]string, 0, len(connectors))
	for _, connector := range connectors {
		p, _ := psetv2.NewPsetFromBase64(connector)
		utx, _ := p.UnsignedTx()
		txid := utx.TxHash().String()
		connectorsTxids = append(connectorsTxids, txid)
	}

	for _, forfeitTx := range forfeitTxs {
		pset, err := psetv2.NewPsetFromBase64(forfeitTx)
		if err != nil {
			return nil, err
		}

		for _, input := range pset.Inputs {
			inputTxid := chainhash.Hash(input.PreviousTxid).String()
			for _, coin := range vtxosToSign {
				if inputTxid == coin.Txid {
					signedPset, err := a.signForfeitTx(ctx, forfeitTx, pset, connectorsTxids)
					if err != nil {
						return nil, err
					}
					signedForfeits = append(signedForfeits, signedPset)
				}
			}
		}
	}

	return signedForfeits, nil
}

func (a *covenantArkClient) signForfeitTx(
	ctx context.Context, txStr string, tx *psetv2.Pset, connectorsTxids []string,
) (string, error) {
	connectorTxid := chainhash.Hash(tx.Inputs[0].PreviousTxid).String()
	connectorFound := false
	for _, id := range connectorsTxids {
		if id == connectorTxid {
			connectorFound = true
			break
		}
	}
	if !connectorFound {
		return "", fmt.Errorf("connector txid %s not found in the connectors list", connectorTxid)
	}

	return a.wallet.SignTransaction(ctx, a.explorer, txStr)
}

func (a *covenantArkClient) coinSelectOnchain(
	ctx context.Context, targetAmount uint64, exclude []explorer.Utxo,
) ([]explorer.Utxo, []explorer.Utxo, uint64, error) {
	offchainAddrs, onchainAddrs, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	net := utils.ToElementsNetwork(a.Network)

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
