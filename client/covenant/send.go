package covenant

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/client/utils"
	"github.com/ark-network/ark/common"
	"github.com/urfave/cli/v2"
)

func (c *covenantLiquidCLI) Send(ctx *cli.Context) error {
	if !ctx.IsSet("receivers") && !ctx.IsSet("to") && !ctx.IsSet("amount") {
		return fmt.Errorf("missing destination, either use --to and --amount to send or --receivers to send to many")
	}
	receivers := ctx.String("receivers")
	to := ctx.String("to")
	amount := ctx.Uint64("amount")

	var receiversJSON []receiver
	if len(receivers) > 0 {
		if err := json.Unmarshal([]byte(receivers), &receiversJSON); err != nil {
			return fmt.Errorf("invalid receivers: %s", err)
		}
	} else {
		receiversJSON = []receiver{
			{
				To:     to,
				Amount: amount,
			},
		}
	}

	if len(receiversJSON) <= 0 {
		return fmt.Errorf("no receivers specified")
	}

	onchainReceivers := make([]receiver, 0)
	offchainReceivers := make([]receiver, 0)

	for _, receiver := range receiversJSON {
		if receiver.isOnchain() {
			onchainReceivers = append(onchainReceivers, receiver)
		} else {
			offchainReceivers = append(offchainReceivers, receiver)
		}
	}

	explorer := utils.NewExplorer(ctx)

	if len(onchainReceivers) > 0 {
		pset, err := sendOnchain(ctx, onchainReceivers)
		if err != nil {
			return err
		}

		txid, err := explorer.Broadcast(pset)
		if err != nil {
			return err
		}

		return utils.PrintJSON(map[string]interface{}{
			"txid": txid,
		})
	}

	if len(offchainReceivers) > 0 {
		if err := sendOffchain(ctx, offchainReceivers); err != nil {
			return err
		}
	}

	return nil
}

func sendOffchain(ctx *cli.Context, receivers []receiver) error {
	withExpiryCoinselect := ctx.Bool("enable-expiry-coinselect")

	offchainAddr, _, _, err := getAddress(ctx)
	if err != nil {
		return err
	}

	_, _, aspPubKey, err := common.DecodeAddress(offchainAddr)
	if err != nil {
		return err
	}

	dust, err := utils.GetDust(ctx)
	if err != nil {
		return err
	}

	receiversOutput := make([]*arkv1.Output, 0)
	sumOfReceivers := uint64(0)

	for _, receiver := range receivers {
		_, _, aspKey, err := common.DecodeAddress(receiver.To)
		if err != nil {
			return fmt.Errorf("invalid receiver address: %s", err)
		}

		if !bytes.Equal(
			aspPubKey.SerializeCompressed(), aspKey.SerializeCompressed(),
		) {
			return fmt.Errorf("invalid receiver address '%s': must be associated with the connected service provider", receiver.To)
		}

		if receiver.Amount < dust {
			return fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount, dust)
		}

		receiversOutput = append(receiversOutput, &arkv1.Output{
			Address: receiver.To,
			Amount:  uint64(receiver.Amount),
		})
		sumOfReceivers += receiver.Amount
	}
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
	selectedCoins, changeAmount, err := coinSelect(vtxos, sumOfReceivers, withExpiryCoinselect, dust)
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

	secKey, err := utils.PrivateKeyFromPassword(ctx)
	if err != nil {
		return err
	}

	registerResponse, err := client.RegisterPayment(
		ctx.Context, &arkv1.RegisterPaymentRequest{Inputs: inputs},
	)
	if err != nil {
		return err
	}

	_, err = client.ClaimPayment(ctx.Context, &arkv1.ClaimPaymentRequest{
		Id:      registerResponse.GetId(),
		Outputs: receiversOutput,
	})
	if err != nil {
		return err
	}

	poolTxID, err := handleRoundStream(
		ctx, client, registerResponse.GetId(),
		selectedCoins, secKey, receiversOutput,
	)
	if err != nil {
		return err
	}

	return utils.PrintJSON(map[string]interface{}{
		"pool_txid": poolTxID,
	})
}

func coinSelect(vtxos []vtxo, amount uint64, sortByExpirationTime bool, dust uint64) ([]vtxo, uint64, error) {
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
