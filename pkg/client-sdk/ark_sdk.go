package arksdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
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

const (
	minRelayFee = 30
	DUST        = 450
)

var (
	explorerUrlMap = map[string]string{
		network.Liquid.Name:  "https://blockstream.info/liquid/api",
		network.Testnet.Name: "https://blockstream.info/liquidtestnet/api",
		network.Regtest.Name: "http://localhost:3001",
	}
)

type ArkClient interface {
	Connect(ctx context.Context) error
	Balance(ctx context.Context, computeExpiryDetails bool) (*BalanceResp, error)
	Onboard(ctx context.Context, amount uint64) (string, error)
	TrustedOnboard(ctx context.Context) (string, error)
	Receive(ctx context.Context) (string, string, error)
	SendOnChain(ctx context.Context, receivers []Receiver) (string, error)
	SendOffChain(
		ctx context.Context, withExpiryCoinselect bool, receivers []Receiver,
	) (string, error)
	ForceRedeem(ctx context.Context) error
	CollaborativeRedeem(
		ctx context.Context, addr string, amount uint64, withExpiryCoinselect bool,
	) (string, error)
}

func New(
	wallet Wallet,
	explorerUrl string,
	protocol TransportProtocol,
	net string,
	aspUrl string,
	aspPubKey string,
) (ArkClient, error) {
	if len(aspUrl) <= 0 {
		return nil, errors.New("invalid ark url")
	}
	if net != "liquid" && net != "testnet" && net != "regtest" {
		return nil, fmt.Errorf("invalid network")
	}

	if len(explorerUrl) > 0 {
		_, n := networkFromString(net)
		if err := testEsploraEndpoint(n, explorerUrl); err != nil {
			return nil, fmt.Errorf("failed to connect with explorer: %s", err)
		}
	} else {
		explorerUrl = explorerUrlMap[net]
	}

	aspPubKeyBytes, err := hex.DecodeString(aspPubKey)
	if err != nil {
		return nil, err
	}

	return &arkClient{
		aspUrl:      aspUrl,
		aspPubKey:   aspPubKeyBytes,
		net:         net,
		explorerUrl: explorerUrl,
		wallet:      wallet,
		protocol:    protocol,
		explorer:    NewExplorer(explorerUrl),
	}, nil
}

type arkClient struct {
	aspUrl              string
	aspPubKey           []byte
	roundLifeTime       int
	unilateralExitDelay int
	net                 string
	explorerUrl         string
	protocol            TransportProtocol

	wallet Wallet

	initiated   bool
	innerClient arkTransportClient

	explorer Explorer
}

const (
	Grpc TransportProtocol = iota
	Rest
)

type TransportProtocol int

func (a *arkClient) Connect(ctx context.Context) error {
	if a.initiated {
		return nil
	}

	transportClient, err := newArkTransportClient(
		a.aspUrl, a.protocol, a.explorer,
	)
	if err != nil {
		return err
	}
	a.innerClient = transportClient

	resp, err := a.innerClient.getInfo(ctx)
	if err != nil {
		return err
	}
	a.roundLifeTime = int(resp.RoundLifetime)
	a.unilateralExitDelay = int(resp.UnilateralExitDelay)

	a.initiated = true

	return nil
}

type BalanceResp struct {
	OnchainBalance  OnchainBalanceResp  `json:"onchain_balance"`
	OffchainBalance OffchainBalanceResp `json:"offchain_balance"`
}

type OnchainBalanceResp struct {
	SpendableAmount uint64                 `json:"spendable_amount"`
	LockedAmount    []LockedOnchainBalance `json:"locked_amount,omitempty"`
}

type LockedOnchainBalance struct {
	SpendableAt string `json:"spendable_at"`
	Amount      uint64 `json:"amount"`
}

type OffchainBalanceResp struct {
	Total          uint64            `json:"total"`
	NextExpiration string            `json:"next_expiration,omitempty"`
	Details        []OffchainDetails `json:"details"`
}

type OffchainDetails struct {
	ExpiryTime string `json:"expiry_time"`
	Amount     uint64 `json:"amount"`
}

type balanceRes struct {
	offchainBalance             uint64
	onchainSpendableBalance     uint64
	onchainLockedBalance        map[int64]uint64
	offchainBalanceByExpiration map[int64]uint64
	err                         error
}

func (a *arkClient) Balance(
	ctx context.Context, computeExpiryDetails bool,
) (*BalanceResp, error) {
	offchainAddr, onchainAddr, redemptionAddr, err := getAddress(
		a.wallet.PubKeySerializeCompressed(), a.aspPubKey, int64(a.unilateralExitDelay), a.net,
	)
	if err != nil {
		return nil, err
	}

	_, liquidNet := networkFromString(a.net)

	wg := &sync.WaitGroup{}
	wg.Add(3)

	chRes := make(chan balanceRes, 3)
	go func() {
		defer wg.Done()
		balance, amountByExpiration, err := a.innerClient.getOffchainBalance(
			ctx, offchainAddr, computeExpiryDetails,
		)
		if err != nil {
			chRes <- balanceRes{
				0,
				0,
				nil,
				nil,
				err,
			}
			return
		}

		chRes <- balanceRes{
			balance,
			0,
			nil,
			amountByExpiration,
			nil,
		}
	}()

	go func() {
		defer wg.Done()
		balance, err := a.explorer.GetBalance(onchainAddr, liquidNet.AssetID)
		if err != nil {
			chRes <- balanceRes{
				0,
				0,
				nil,
				nil,
				err,
			}
			return
		}
		chRes <- balanceRes{
			0,
			balance,
			nil,
			nil,
			nil,
		}
	}()

	go func() {
		defer wg.Done()

		spendableBalance, lockedBalance, err := a.explorer.GetRedeemedVtxosBalance(
			redemptionAddr, int64(a.unilateralExitDelay),
		)
		if err != nil {
			chRes <- balanceRes{
				0,
				0,
				nil,
				nil,
				err,
			}
			return
		}

		chRes <- balanceRes{
			0,
			spendableBalance,
			lockedBalance,
			nil,
			err,
		}
	}()

	wg.Wait()

	lockedOnchainBalance := []LockedOnchainBalance{}
	details := make([]OffchainDetails, 0)
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

				fancyTime := time.Unix(timestamp, 0).Format("2006-01-02 15:04:05")
				details = append(
					details,
					OffchainDetails{
						ExpiryTime: fancyTime,
						Amount:     amount,
					},
				)
			}
		}
		if res.onchainLockedBalance != nil {
			for timestamp, amount := range res.onchainLockedBalance {
				fancyTime := time.Unix(timestamp, 0).Format("2006-01-02 15:04:05")
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
			fancyTimeExpiration = t.Format("2006-01-02 15:04:05")
		}
	}

	response := &BalanceResp{
		OnchainBalance: OnchainBalanceResp{
			SpendableAmount: onchainBalance,
			LockedAmount:    lockedOnchainBalance,
		},
		OffchainBalance: OffchainBalanceResp{
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

	_, net := networkFromString(a.net)
	userPubKey := a.wallet.PubKeySerializeCompressed()

	congestionTreeLeaf := tree.Receiver{
		Pubkey: hex.EncodeToString(userPubKey),
		Amount: amount,
	}

	aspPubkey, err := secp256k1.ParsePubKey(a.aspPubKey)
	if err != nil {
		return "", nil
	}

	treeFactoryFn, sharedOutputScript, sharedOutputAmount, err := tree.CraftCongestionTree(
		net.AssetID,
		aspPubkey,
		[]tree.Receiver{congestionTreeLeaf},
		minRelayFee,
		int64(a.roundLifeTime),
		int64(a.unilateralExitDelay),
	)
	if err != nil {
		return "", err
	}

	pay, err := payment.FromScript(sharedOutputScript, net, nil)
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

	pset, err := a.sendOnchain([]Receiver{onchainReceiver})
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

	_, err = a.innerClient.onboard(ctx, &arkv1.OnboardRequest{
		BoardingTx:     pset,
		CongestionTree: castCongestionTree(congestionTree),
		UserPubkey:     hex.EncodeToString(userPubKey),
	})
	if err != nil {
		return "", err
	}

	return txid, nil
}

func (a *arkClient) sendOnchain(receivers []Receiver) (string, error) {
	pset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return "", err
	}
	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return "", err
	}

	_, net := networkFromString(a.net)

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
		targetAmount, nil,
	)
	if err != nil {
		return "", err
	}

	if err := a.addInputs(updater, utxos, delayedUtxos, net); err != nil {
		return "", err
	}

	if change > 0 {
		_, changeAddr, _, err := getAddress(
			a.wallet.PubKeySerializeCompressed(), a.aspPubKey, int64(a.unilateralExitDelay), a.net,
		)
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
			feeAmount-change, append(utxos, delayedUtxos...),
		)
		if err != nil {
			return "", err
		}

		if err := a.addInputs(updater, selected, delayedSelected, net); err != nil {
			return "", err
		}

		if newChange > 0 {
			_, changeAddr, _, err := getAddress(
				a.wallet.PubKeySerializeCompressed(), a.aspPubKey, int64(a.unilateralExitDelay), a.net,
			)
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

	_, onchainAddr, _, err := getAddress(
		a.wallet.PubKeySerializeCompressed(), a.aspPubKey, int64(a.unilateralExitDelay), a.net,
	)

	if err := a.wallet.SignPsetForAddress(updater.Pset, onchainAddr); err != nil {
		return "", err
	}

	if err := psetv2.FinalizeAll(updater.Pset); err != nil {
		return "", err
	}

	return updater.Pset.ToBase64()
}

func (a *arkClient) sendOffchain(
	ctx context.Context, withExpiryCoinselect bool, receivers []Receiver,
) (string, error) {
	offchainAddr, _, _, err := getAddress(
		a.wallet.PubKeySerializeCompressed(), a.aspPubKey, int64(a.unilateralExitDelay), a.net,
	)
	if err != nil {
		return "", err
	}

	_, _, aspPubKey, err := common.DecodeAddress(offchainAddr)
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

	vtxos, err := a.innerClient.getSpendableVtxos(ctx, offchainAddr, withExpiryCoinselect)
	if err != nil {
		return "", err
	}
	selectedCoins, changeAmount, err := coinSelect(vtxos, sumOfReceivers, withExpiryCoinselect)
	if err != nil {
		return "", err
	}

	if changeAmount > 0 {
		changeReceiver := &arkv1.Output{
			Address: offchainAddr,
			Amount:  changeAmount,
		}
		receiversOutput = append(receiversOutput, changeReceiver)
	}

	inputs := make([]*arkv1.Input, 0, len(selectedCoins))

	for _, coin := range selectedCoins {
		inputs = append(inputs, &arkv1.Input{
			Txid: coin.txid,
			Vout: coin.vout,
		})
	}

	registerResponse, err := a.innerClient.registerPayment(
		ctx, &arkv1.RegisterPaymentRequest{Inputs: inputs},
	)
	if err != nil {
		return "", err
	}

	_, err = a.innerClient.claimPayment(ctx, &arkv1.ClaimPaymentRequest{
		Id:      registerResponse.GetId(),
		Outputs: receiversOutput,
	})
	if err != nil {
		return "", err
	}

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
	updater *psetv2.Updater, utxos, delayedUtxos []utxo, net *network.Network,
) error {
	_, onchainAddr, _, err := getAddress(
		a.wallet.PubKeySerializeCompressed(), a.aspPubKey, int64(a.unilateralExitDelay), a.net,
	)
	if err != nil {
		return err
	}

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
		aspPubkey, err := secp256k1.ParsePubKey(a.aspPubKey)
		if err != nil {
			return err
		}

		vtxoTapKey, leafProof, err := computeVtxoTaprootScript(
			a.wallet.PubKey(), aspPubkey, uint(a.unilateralExitDelay),
		)
		if err != nil {
			return err
		}

		pay, err := payment.FromTweakedKey(vtxoTapKey, net, nil)
		if err != nil {
			return err
		}

		addr, err := pay.TaprootAddress()
		if err != nil {
			return err
		}

		script, err := address.ToOutputScript(addr)
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
				uint(a.unilateralExitDelay),
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

func (r *Receiver) isOnchain() bool {
	_, err := address.ToOutputScript(r.To)
	return err == nil
}

func (a *arkClient) TrustedOnboard(ctx context.Context) (string, error) {
	resp, err := a.innerClient.trustedOnboarding(
		ctx, &arkv1.TrustedOnboardingRequest{
			UserPubkey: hex.EncodeToString(a.wallet.PubKeySerializeCompressed()),
		},
	)
	if err != nil {
		return "", err
	}

	return resp.Address, nil
}

func (a *arkClient) Receive(ctx context.Context) (string, string, error) {
	offchainAddr, onchainAddr, _, err := getAddress(
		a.wallet.PubKeySerializeCompressed(), a.aspPubKey, int64(a.unilateralExitDelay), a.net,
	)
	if err != nil {
		return "", "", err
	}

	return offchainAddr, onchainAddr, nil
}

func (a *arkClient) SendOnChain(
	ctx context.Context, receivers []Receiver,
) (string, error) {
	for _, receiver := range receivers {
		if !receiver.isOnchain() {
			return "", fmt.Errorf("invalid receiver address '%s': must be onchain", receiver.To)
		}
	}

	return a.sendOnchain(receivers)
}

func (a *arkClient) SendOffChain(
	ctx context.Context, withExpiryCoinselect bool, receivers []Receiver,
) (string, error) {
	for _, receiver := range receivers {
		if receiver.isOnchain() {
			return "", fmt.Errorf("invalid receiver address '%s': must be offchain", receiver.To)
		}
	}

	return a.sendOffchain(ctx, withExpiryCoinselect, receivers)
}

func (a *arkClient) coinSelectOnchain(
	targetAmount uint64, exclude []utxo,
) ([]utxo, []utxo, uint64, error) {
	_, onchainAddr, _, err := getAddress(
		a.wallet.PubKeySerializeCompressed(), a.aspPubKey, int64(a.unilateralExitDelay), a.net,
	)
	if err != nil {
		return nil, nil, 0, err
	}

	fromExplorer, err := a.explorer.GetUtxos(onchainAddr)
	if err != nil {
		return nil, nil, 0, err
	}

	utxos := make([]utxo, 0)
	selectedAmount := uint64(0)
	for _, utxo := range fromExplorer {
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

	aspPubkey, err := secp256k1.ParsePubKey(a.aspPubKey)
	if err != nil {
		return nil, nil, 0, err
	}

	vtxoTapKey, _, err := computeVtxoTaprootScript(
		a.wallet.PubKey(), aspPubkey, uint(a.unilateralExitDelay),
	)
	if err != nil {
		return nil, nil, 0, err
	}

	_, net := networkFromString(a.net)

	pay, err := payment.FromTweakedKey(vtxoTapKey, net, nil)
	if err != nil {
		return nil, nil, 0, err
	}

	addr, err := pay.TaprootAddress()
	if err != nil {
		return nil, nil, 0, err
	}

	fromExplorer, err = a.explorer.GetUtxos(addr)
	if err != nil {
		return nil, nil, 0, err
	}

	delayedUtxos := make([]utxo, 0)
	for _, utxo := range fromExplorer {
		if selectedAmount >= targetAmount {
			break
		}

		availableAt := time.Unix(utxo.Status.Blocktime, 0).Add(
			time.Duration(a.unilateralExitDelay) * time.Second,
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

func (a *arkClient) handleRoundStream(
	ctx context.Context,
	paymentID string,
	vtxosToSign []vtxo,
	receivers []*arkv1.Output,
) (poolTxID string, err error) {
	stream, err := a.innerClient.getEventStream(ctx, &arkv1.GetEventStreamRequest{})
	if err != nil {
		return "", err
	}

	var pingStop func()
	pingReq := &arkv1.PingRequest{
		PaymentId: paymentID,
	}
	for pingStop == nil {
		pingStop = a.ping(ctx, pingReq)
	}

	defer pingStop()

	for {
		event, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		if e := event.GetRoundFailed(); e != nil {
			pingStop()
			return "", fmt.Errorf("round failed: %s", e.GetReason())
		}

		if e := event.GetRoundFinalization(); e != nil {
			// stop pinging as soon as we receive some forfeit txs
			pingStop()
			log.Infoln("round finalization started")

			poolTx := e.GetPoolTx()
			ptx, err := psetv2.NewPsetFromBase64(poolTx)
			if err != nil {
				return "", err
			}

			congestionTree, err := toCongestionTree(e.GetCongestionTree())
			if err != nil {
				return "", err
			}

			connectors := e.GetConnectors()

			aspPubkey, err := secp256k1.ParsePubKey(a.aspPubKey)
			if err != nil {
				return "", err
			}

			if !isOnchainOnly(receivers) {
				// validate the congestion tree
				if err := tree.ValidateCongestionTree(
					congestionTree, poolTx, aspPubkey, int64(a.roundLifeTime),
				); err != nil {
					return "", err
				}
			}

			if err := common.ValidateConnectors(poolTx, connectors); err != nil {
				return "", err
			}

			for _, receiver := range receivers {
				isOnChain, onchainScript, userPubkey, err := decodeReceiverAddress(
					receiver.Address,
				)
				if err != nil {
					return "", err
				}

				if isOnChain {
					// collaborative exit case
					// search for the output in the pool tx
					found := false
					for _, output := range ptx.Outputs {
						if bytes.Equal(output.Script, onchainScript) {
							if output.Value != receiver.Amount {
								return "", fmt.Errorf(
									"invalid collaborative exit output amount: got %d, want %d",
									output.Value, receiver.Amount,
								)
							}

							found = true
							break
						}
					}

					if !found {
						return "", fmt.Errorf(
							"collaborative exit output not found: %s", receiver.Address,
						)
					}

					continue
				}

				// off-chain send case
				// search for the output in congestion tree
				found := false

				// compute the receiver output taproot key
				outputTapKey, _, err := computeVtxoTaprootScript(
					userPubkey, aspPubkey, uint(a.unilateralExitDelay),
				)
				if err != nil {
					return "", err
				}

				leaves := congestionTree.Leaves()
				for _, leaf := range leaves {
					tx, err := psetv2.NewPsetFromBase64(leaf.Tx)
					if err != nil {
						return "", err
					}

					for _, output := range tx.Outputs {
						if len(output.Script) == 0 {
							continue
						}
						if bytes.Equal(
							output.Script[2:], schnorr.SerializePubKey(outputTapKey),
						) {
							if output.Value != receiver.Amount {
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
					return "", fmt.Errorf(
						"off-chain send output not found: %s", receiver.Address,
					)
				}
			}

			log.Infoln("congestion tree validated")

			forfeits := e.GetForfeitTxs()
			signedForfeits := make([]string, 0)

			log.Infoln("signing forfeit txs... ")

			connectorsTxids := make([]string, 0, len(connectors))
			for _, connector := range connectors {
				p, _ := psetv2.NewPsetFromBase64(connector)
				utx, _ := p.UnsignedTx()
				txid := utx.TxHash().String()

				connectorsTxids = append(connectorsTxids, txid)
			}

			for _, forfeit := range forfeits {
				pset, err := psetv2.NewPsetFromBase64(forfeit)
				if err != nil {
					return "", err
				}

				for _, input := range pset.Inputs {
					inputTxid := chainhash.Hash(input.PreviousTxid).String()

					for _, coin := range vtxosToSign {
						// check if it contains one of the input to sign
						if inputTxid == coin.txid {
							// verify that the connector is in the connectors list
							connectorTxid := chainhash.Hash(pset.Inputs[0].PreviousTxid).String()
							connectorFound := false
							for _, txid := range connectorsTxids {
								if txid == connectorTxid {
									connectorFound = true
									break
								}
							}

							if !connectorFound {
								return "", fmt.Errorf("connector txid %s not found in the connectors list", connectorTxid)
							}

							_, onchainAddr, _, err := getAddress(
								a.wallet.PubKeySerializeCompressed(), a.aspPubKey, int64(a.unilateralExitDelay), a.net,
							)
							if err != nil {
								return "", err
							}

							if err := a.wallet.SignPsetForAddress(pset, onchainAddr); err != nil {
								return "", err
							}

							signedPset, err := pset.ToBase64()
							if err != nil {
								return "", err
							}

							signedForfeits = append(signedForfeits, signedPset)
						}
					}
				}
			}

			// if no forfeit txs have been signed, start pinging again and wait for the next round
			if len(signedForfeits) == 0 {
				log.Infoln("no forfeit txs to sign, waiting for the next round...")
				pingStop = nil
				for pingStop == nil {
					pingStop = a.ping(ctx, pingReq)
				}
				continue
			}

			log.Infof("%d signed", len(signedForfeits))
			log.Infoln("finalizing payment... ")
			_, err = a.innerClient.finalizePayment(ctx, &arkv1.FinalizePaymentRequest{
				SignedForfeitTxs: signedForfeits,
			})
			if err != nil {
				return "", err
			}
			log.Infoln("done.")
			log.Infoln("waiting for round finalization...")

			continue
		}

		if event.GetRoundFinalized() != nil {
			return event.GetRoundFinalized().GetPoolTxid(), nil
		}
	}

	return "", fmt.Errorf("stream closed unexpectedly")
}

func (a *arkClient) ForceRedeem(ctx context.Context) error {
	offchainAddr, _, _, err := getAddress(
		a.wallet.PubKeySerializeCompressed(), a.aspPubKey, int64(a.unilateralExitDelay), a.net,
	)
	if err != nil {
		return err
	}

	vtxos, err := a.innerClient.getSpendableVtxos(ctx, offchainAddr, false)
	if err != nil {
		return err
	}

	totalVtxosAmount := uint64(0)

	for _, vtxo := range vtxos {
		totalVtxosAmount += vtxo.amount
	}

	// transactionsMap avoid duplicates
	transactionsMap := make(map[string]struct{}, 0)
	transactions := make([]string, 0)

	redeemBranches, err := a.innerClient.getRedeemBranches(ctx, a.explorer, vtxos)
	if err != nil {
		return err
	}

	for _, branch := range redeemBranches {
		branchTxs, err := branch.redeemPath()
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
	ctx context.Context, addr string, amount uint64, withExpiryCoinselect bool,
) (string, error) {
	if _, err := address.ToOutputScript(addr); err != nil {
		return "", fmt.Errorf("invalid onchain address")
	}

	net, err := address.NetworkForAddress(addr)
	if err != nil {
		return "", fmt.Errorf("invalid onchain address: unknown network")
	}
	_, liquidNet := networkFromString(a.net)
	if net.Name != liquidNet.Name {
		return "", fmt.Errorf("invalid onchain address: must be for %s network", liquidNet.Name)
	}

	if isConf, _ := address.IsConfidential(addr); isConf {
		info, _ := address.FromConfidential(addr)
		addr = info.Address
	}

	offchainAddr, _, _, err := getAddress(
		a.wallet.PubKeySerializeCompressed(), a.aspPubKey, int64(a.unilateralExitDelay), a.net,
	)

	if err != nil {
		return "", err
	}

	receivers := []*arkv1.Output{
		{
			Address: addr,
			Amount:  amount,
		},
	}

	vtxos, err := a.innerClient.getSpendableVtxos(ctx, offchainAddr, withExpiryCoinselect)
	if err != nil {
		return "", err
	}

	selectedCoins, changeAmount, err := coinSelect(vtxos, amount, withExpiryCoinselect)
	if err != nil {
		return "", err
	}

	if changeAmount > 0 {
		receivers = append(receivers, &arkv1.Output{
			Address: offchainAddr,
			Amount:  changeAmount,
		})
	}

	inputs := make([]*arkv1.Input, 0, len(selectedCoins))

	for _, coin := range selectedCoins {
		inputs = append(inputs, &arkv1.Input{
			Txid: coin.txid,
			Vout: coin.vout,
		})
	}

	registerResponse, err := a.innerClient.registerPayment(ctx, &arkv1.RegisterPaymentRequest{
		Inputs: inputs,
	})
	if err != nil {
		return "", err
	}

	_, err = a.innerClient.claimPayment(ctx, &arkv1.ClaimPaymentRequest{
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

func (a *arkClient) ping(
	ctx context.Context, req *arkv1.PingRequest,
) func() {
	_, err := a.innerClient.ping(ctx, req)
	if err != nil {
		return nil
	}

	ticker := time.NewTicker(5 * time.Second)

	go func(t *time.Ticker) {
		for range t.C {
			// nolint
			a.innerClient.ping(ctx, req)
		}
	}(ticker)

	return ticker.Stop
}
