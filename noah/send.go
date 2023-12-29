package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/psetv2"
)

type receiver struct {
	To     string `json:"to"`
	Amount uint64 `json:"amount"`
}

var (
	receiversFlag = cli.StringFlag{
		Name:     "receivers",
		Usage:    "receivers of the send transaction, JSON encoded: '[{\"to\": \"<...>\", \"amount\": <...>}, ...]'",
		Value:    "",
		Required: true,
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

	stream, err := client.GetEventStream(ctx.Context, &arkv1.GetEventStreamRequest{})
	if err != nil {
		return err
	}

	var pingStop func()
	pingReq := &arkv1.PingRequest{
		PaymentId: registerResponse.GetId(),
	}
	for pingStop == nil {
		pingStop = ping(ctx, client, pingReq)
	}

	for {
		event, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if event.GetRoundFailed() != nil {
			return fmt.Errorf("round failed: %s", event.GetRoundFailed().GetReason())
		}

		if event.GetRoundFinalization() != nil {
			// stop pinging as soon as we receive some forfeit txs
			pingStop()
			forfeits := event.GetRoundFinalization().GetForfeitTxs()
			signedForfeits := make([]string, 0)

			for _, forfeit := range forfeits {
				pset, err := psetv2.NewPsetFromBase64(forfeit)
				if err != nil {
					return err
				}

				// check if it contains one of the input to sign
				for _, input := range pset.Inputs {
					inputTxid := chainhash.Hash(input.PreviousTxid).String()

					for _, coin := range selectedCoins {
						if inputTxid == coin.txid {
							// TODO: sign the vtxo input
							signedForfeits = append(signedForfeits, forfeit)
						}
					}
				}
			}

			// if no forfeit txs have been signed, start pinging again and wait for the next round
			if len(signedForfeits) == 0 {
				pingStop = nil
				for pingStop == nil {
					pingStop = ping(ctx, client, pingReq)
				}
				continue
			}

			_, err := client.FinalizePayment(ctx.Context, &arkv1.FinalizePaymentRequest{
				SignedForfeitTxs: signedForfeits,
			})
			if err != nil {
				return err
			}

			continue
		}

		if event.GetRoundFinalized() != nil {
			return printJSON(map[string]interface{}{
				"pool_txid": event.GetRoundFinalized().GetPoolTxid(),
			})
		}
	}

	return nil
}

// send 1 ping message every 5 seconds to signal to the ark service that we are still alive
// returns a function that can be used to stop the pinging
func ping(ctx *cli.Context, client arkv1.ArkServiceClient, req *arkv1.PingRequest) func() {
	_, err := client.Ping(ctx.Context, req)
	if err != nil {
		return nil
	}

	ticker := time.NewTicker(5 * time.Second)

	go func(t *time.Ticker) {
		for range t.C {
			client.Ping(ctx.Context, req)
		}
	}(ticker)

	return ticker.Stop
}
