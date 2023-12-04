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
	Amount int64  `json:"amount"`
}

var (
	receiversFlag = cli.StringFlag{
		Name:     "receivers",
		Usage:    "receivers of the send transaction, JSON encoded: '[{\"to\": \"<...>\", \"amount\": <...>}, ...]'",
		Value:    "",
		Required: true,
	}
)

var sendCommand = cli.Command{
	Name:   "send",
	Usage:  "Send VTXOs to a list of addresses",
	Action: sendAction,
	Flags:  []cli.Flag{&receiversFlag},
}

func sendAction(ctx *cli.Context) error {
	receivers := ctx.String("receivers")

	// parse json encoded receivers
	var receiversJSON []receiver
	if err := json.Unmarshal([]byte(receivers), &receiversJSON); err != nil {
		return fmt.Errorf("invalid receivers: %s", err)
	}

	if len(receiversJSON) <= 0 {
		return fmt.Errorf("no receivers specified")
	}

	aspPubKey, err := getServiceProviderPublicKey()
	if err != nil {
		return err
	}

	receiversOutput := make([]*arkv1.Output, 0)
	sumOfReceivers := uint64(0)

	for _, receiver := range receiversJSON {
		_, userKey, aspKey, err := common.DecodeAddress(receiver.To)
		if err != nil {
			return fmt.Errorf("invalid receiver address: %s", err)
		}

		if !bytes.Equal(aspPubKey.SerializeCompressed(), aspKey.SerializeCompressed()) {
			return fmt.Errorf("invalid receiver address '%s': must be associated with the connected service provider", receiver.To)
		}

		if receiver.Amount <= 0 {
			return fmt.Errorf("invalid amount: %d", receiver.Amount)
		}

		encodedKey, err := common.EncodePubKey(common.MainNet.PubKey, userKey)
		if err != nil {
			return err
		}

		receiversOutput = append(receiversOutput, &arkv1.Output{
			Pubkey: encodedKey,
			Amount: uint64(receiver.Amount),
		})
	}
	client, close, err := getArkClient(ctx)
	if err != nil {
		return err
	}
	defer close()

	vtxos, err := getVtxos(ctx, client)
	if err != nil {
		return err
	}

	selectedCoins, changeAmount, err := coinSelect(vtxos, sumOfReceivers)
	if err != nil {
		return err
	}

	if changeAmount > 0 {
		walletPrvKey, err := privateKeyFromPassword()
		if err != nil {
			return err
		}

		walletPubKey := walletPrvKey.PubKey()
		encodedPubKey, err := common.EncodePubKey(common.MainNet.PubKey, walletPubKey)
		if err != nil {
			return err
		}

		changeReceiver := &arkv1.Output{
			Pubkey: encodedPubKey,
			Amount: changeAmount,
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

	pingStop := ping(ctx, client, &arkv1.PingRequest{
		PaymentId: registerResponse.GetId(),
	})

	defer pingStop()

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
			forfeits := event.GetRoundFinalization().GetForfeitTxs()
			fmt.Printf("number of forfeits in the round: %d\n", len(forfeits))
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
							// to sign
							signedForfeits = append(signedForfeits, forfeit)
						}
					}
				}
			}

			if len(signedForfeits) == 0 {
				return fmt.Errorf("no forfeit to sign")
			}

			_, err := client.FinalizePayment(ctx.Context, &arkv1.FinalizePaymentRequest{
				SignedForfeits: signedForfeits,
			})
			if err != nil {
				return err
			}

			continue
		}

		if event.GetRoundFinalized() != nil {
			fmt.Printf("vtxos sent by pool %s\n", event.GetRoundFinalized().GetPoolTxid())
			return nil
		}
	}

	return nil
}

// send 1 ping message every minute (55 secs) to signal to the ark service that we are still alive
// returns a function that can be used to stop the pinging
func ping(ctx *cli.Context, client arkv1.ArkServiceClient, req *arkv1.PingRequest) func() {
	ticker := time.NewTicker(55 * time.Second)

	go func() {
		for range ticker.C {
			_, err := client.Ping(ctx.Context, req)
			if err != nil {
				fmt.Println("error while pinging ark service:", err)
			}
		}
	}()

	return ticker.Stop
}
