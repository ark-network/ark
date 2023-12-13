package main

import (
	"context"
	"fmt"
	"io"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/urfave/cli/v2"
)

var faucetCommand = cli.Command{
	Name:   "faucet",
	Usage:  "Faucet your wallet",
	Action: faucetAction,
}

func faucetAction(ctx *cli.Context) error {
	addr, err := getAddress()
	if err != nil {
		return err
	}

	client, close, err := getArkClient(ctx)
	if err != nil {
		return err
	}
	defer close()

	_, err = client.Faucet(ctx.Context, &arkv1.FaucetRequest{
		Address: addr,
	})
	if err != nil {
		return err
	}

	eventStream, err := client.GetEventStream(ctx.Context, &arkv1.GetEventStreamRequest{})
	if err != nil {
		return err
	}

	for {
		event, err := eventStream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if event.GetRoundFinalization() != nil {
			if _, err := client.FinalizePayment(context.Background(), &arkv1.FinalizePaymentRequest{
				SignedForfeitTxs: event.GetRoundFinalization().GetForfeitTxs(),
			}); err != nil {
				return err
			}
		}

		if event.GetRoundFailed() != nil {
			return fmt.Errorf("faucet failed: %s", event.GetRoundFailed().GetReason())
		}

		if event.GetRoundFinalized() != nil {
			return printJSON(map[string]interface{}{
				"poolTxId": event.GetRoundFinalized().GetPoolTxid(),
			})
		}
	}

	return nil
}
