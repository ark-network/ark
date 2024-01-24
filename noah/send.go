package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/urfave/cli/v2"
)

type receiver struct {
	To     string `json:"to"`
	Amount uint64 `json:"amount"`
}

var (
	receiversFlag = cli.StringFlag{
		Name:  "receivers",
		Usage: "receivers of the send transaction, JSON encoded: '[{\"to\": \"<...>\", \"amount\": <...>}, ...]'",
	}
	toFlag = cli.StringFlag{
		Name:  "to",
		Usage: "ark address of the recipient",
	}
	amountFlag = cli.Uint64Flag{
		Name:  "amount",
		Usage: "amount to send in sats",
	}
)

var sendCommand = cli.Command{
	Name:   "send",
	Usage:  "Send VTXOs to a list of addresses",
	Action: sendAction,
	Flags:  []cli.Flag{&receiversFlag, &toFlag, &amountFlag},
}

func sendAction(ctx *cli.Context) error {
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

	offchainAddr, _, err := getAddress()
	if err != nil {
		return err
	}

	_, _, aspPubKey, err := common.DecodeAddress(offchainAddr)
	if err != nil {
		return err
	}

	receiversOutput := make([]*arkv1.Output, 0)
	sumOfReceivers := uint64(0)

	for _, receiver := range receiversJSON {
		_, _, aspKey, err := common.DecodeAddress(receiver.To)
		if err != nil {
			return fmt.Errorf("invalid receiver address: %s", err)
		}

		if !bytes.Equal(aspPubKey.SerializeCompressed(), aspKey.SerializeCompressed()) {
			return fmt.Errorf("invalid receiver address '%s': must be associated with the connected service provider", receiver.To)
		}

		if receiver.Amount <= 0 {
			return fmt.Errorf("invalid amount: %d", receiver.Amount)
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

	vtxos, err := getVtxos(ctx, client, offchainAddr)
	if err != nil {
		return err
	}

	selectedCoins, changeAmount, err := coinSelect(vtxos, sumOfReceivers)
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

	secKey, err := privateKeyFromPassword()
	if err != nil {
		return err
	}

	registerResponse, err := client.RegisterPayment(ctx.Context, &arkv1.RegisterPaymentRequest{
		Inputs: inputs,
	})
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
		ctx,
		client,
		registerResponse.GetId(),
		selectedCoins,
		secKey,
		receiversOutput,
	)
	if err != nil {
		return err
	}

	if err := printJSON(map[string]interface{}{
		"pool_txid": poolTxID,
	}); err != nil {
		return err
	}

	return nil
}
