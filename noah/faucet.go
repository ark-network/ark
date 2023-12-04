package main

import (
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

	return nil
}
