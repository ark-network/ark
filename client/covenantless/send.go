package covenantless

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/ark-network/ark-cli/utils"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/urfave/cli/v2"
)

func (c *clArkBitcoinCLI) SendAsync(ctx *cli.Context) error {
	receiver := ctx.String("to")
	amount := ctx.Uint64("amount")

	if receiver == "" {
		return fmt.Errorf("receiver address is required")
	}

	isOnchain, _, _, err := decodeReceiverAddress(receiver)
	if err != nil {
		return err
	}

	if isOnchain {
		return fmt.Errorf("receiver address is onchain")
	}

	withExpiryCoinselect := ctx.Bool("enable-expiry-coinselect")

	offchainAddr, _, _, err := getAddress(ctx)
	if err != nil {
		return err
	}

	_, _, aspPubKey, err := common.DecodeAddress(offchainAddr)
	if err != nil {
		return err
	}

	receiversOutput := make([]*arkv1.Output, 0)
	sumOfReceivers := uint64(0)

	_, _, aspKey, err := common.DecodeAddress(receiver)
	if err != nil {
		return fmt.Errorf("invalid receiver address: %s", err)
	}

	if !bytes.Equal(
		aspPubKey.SerializeCompressed(), aspKey.SerializeCompressed(),
	) {
		return fmt.Errorf("invalid receiver address '%s': must be associated with the connected service provider", receiver)
	}

	if amount < dust {
		return fmt.Errorf("invalid amount (%d), must be greater than dust %d", amount, dust)
	}

	receiversOutput = append(receiversOutput, &arkv1.Output{
		Address: receiver,
		Amount:  amount,
	})
	sumOfReceivers += amount

	client, close, err := getClientFromState(ctx)
	if err != nil {
		return err
	}
	defer close()

	explorer := utils.NewExplorer(ctx)

	vtxos, err := getVtxos(ctx, explorer, client, offchainAddr, withExpiryCoinselect)
	if err != nil {
		return err
	}
	selectedCoins, changeAmount, err := coinSelect(vtxos, sumOfReceivers, withExpiryCoinselect)
	if err != nil {
		return err
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

	resp, err := client.CreatePayment(
		ctx.Context, &arkv1.CreatePaymentRequest{
			Inputs:  inputs,
			Outputs: receiversOutput,
		})
	if err != nil {
		return err
	}

	// TODO verify the redeem tx signature
	fmt.Println("Payment created")
	fmt.Println("Signing forfeit...")

	seckey, err := utils.PrivateKeyFromPassword(ctx)
	if err != nil {
		return err
	}

	signedUnconditionalForfeitTxs := make([]string, 0, len(resp.UsignedUnconditionalForfeitTxs))
	for _, tx := range resp.UsignedUnconditionalForfeitTxs {
		forfeitPtx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		if err != nil {
			return err
		}

		if err := signPsbt(ctx, forfeitPtx, explorer, seckey); err != nil {
			return err
		}

		signedForfeitTx, err := forfeitPtx.B64Encode()
		if err != nil {
			return err
		}

		signedUnconditionalForfeitTxs = append(signedUnconditionalForfeitTxs, signedForfeitTx)
	}

	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(resp.SignedRedeemTx), true)
	if err != nil {
		return err
	}

	if err := signPsbt(ctx, redeemPtx, explorer, seckey); err != nil {
		return err
	}

	signedRedeem, err := redeemPtx.B64Encode()
	if err != nil {
		return err
	}

	if _, err = client.CompletePayment(ctx.Context, &arkv1.CompletePaymentRequest{
		SignedRedeemTx:                signedRedeem,
		SignedUnconditionalForfeitTxs: signedUnconditionalForfeitTxs,
	}); err != nil {
		return err
	}

	return nil
}

func coinSelect(vtxos []vtxo, amount uint64, sortByExpirationTime bool) ([]vtxo, uint64, error) {
	selected := make([]vtxo, 0)
	notSelected := make([]vtxo, 0)
	selectedAmount := uint64(0)

	if sortByExpirationTime {
		// sort vtxos by expiration (older first)
		sort.SliceStable(vtxos, func(i, j int) bool {
			if vtxos[i].expireAt == nil || vtxos[j].expireAt == nil {
				return false
			}

			return vtxos[i].expireAt.Before(*vtxos[j].expireAt)
		})
	}

	for _, vtxo := range vtxos {
		if selectedAmount >= amount {
			notSelected = append(notSelected, vtxo)
			break
		}

		selected = append(selected, vtxo)
		selectedAmount += vtxo.amount
	}

	if selectedAmount < amount {
		return nil, 0, fmt.Errorf("not enough funds to cover amount%d", amount)
	}

	change := selectedAmount - amount

	if change < dust {
		if len(notSelected) > 0 {
			selected = append(selected, notSelected[0])
			change += notSelected[0].amount
		}
	}

	return selected, change, nil
}
