package main

import (
	"github.com/urfave/cli/v2"
)

var balanceCommand = cli.Command{
	Name:   "balance",
	Usage:  "Print balance of the Noah wallet",
	Action: balanceAction,
}

func balanceAction(ctx *cli.Context) error {
	client, close, err := getArkClient(ctx)
	if err != nil {
		return err
	}
	defer close()

	vtxos, err := getVtxos(ctx, client)
	if err != nil {
		return err
	}

	balance := computeBalance(vtxos)

	return printJSON(map[string]interface{}{
		"balance": balance,
	})
}
