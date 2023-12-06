package main

import (
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/urfave/cli/v2"
)

var configCommand = cli.Command{
	Name:   "config",
	Usage:  "Print local configuration of the Noah CLI",
	Action: printConfigAction,
	Subcommands: []*cli.Command{
		{
			Name:   "connect",
			Usage:  "connect <ARK_URL>",
			Action: connectAction,
		},
	},
}

func printConfigAction(ctx *cli.Context) error {
	state, err := getState()
	if err != nil {
		return err
	}

	return printJSON(state)
}

func connectAction(ctx *cli.Context) error {
	if ctx.NArg() != 1 {
		return fmt.Errorf("missing ark URL")
	}

	url := ctx.Args().First()

	updateState := map[string]string{
		"ark_url": url,
	}

	if err := setState(updateState); err != nil {
		return err
	}

	client, close, err := getArkClient(ctx)
	if err != nil {
		return err
	}
	defer close()

	resp, err := client.GetPubkey(ctx.Context, &arkv1.GetPubkeyRequest{})
	if err != nil {
		return err
	}

	updateState = map[string]string{
		"ark_pubkey": resp.Pubkey,
	}

	if err := setState(updateState); err != nil {
		return err
	}

	return printJSON(map[string]string{
		"ark_url":    url,
		"ark_pubkey": resp.Pubkey,
	})
}
