package main

import (
	"context"
	"fmt"
	"io"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/urfave/cli/v2"
)

// the faucet command is not included by default in the main.go file
// it lets to include the command if and only if the faucet.go file is included in binary
func init() {
	commands = append(commands, &faucetCommand)
}

var faucetCommand = cli.Command{
	Name:   "faucet",
	Usage:  "Faucet your wallet",
	Action: faucetAction,
}

func faucetAction(ctx *cli.Context) error {
	addr, _, err := getAddress()
	if err != nil {
		return err
	}

	client, close, err := getClientFromState(ctx)
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
				"pool_txid": event.GetRoundFinalized().GetPoolTxid(),
			})
		}
	}

	return nil
}
