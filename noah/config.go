package main

import (
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/urfave/cli/v2"
)

var rpcUrlFlag = cli.StringFlag{
	Name:  "rpc",
	Usage: "ark rpc URL",
	Value: "",
}

var configCommand = cli.Command{
	Name:   "config",
	Usage:  "Print local configuration of the Noah CLI",
	Action: printConfigAction,
	Subcommands: []*cli.Command{
		{
			Name:   "connect",
			Usage:  "connect <ARK_URL> [--rpc <RPC_URL>]",
			Action: connectAction,
			Flags: []cli.Flag{
				&rpcUrlFlag,
			},
		},
	},
}

func printConfigAction(ctx *cli.Context) error {
	state, err := getState()
	if err != nil {
		return err
	}

	for key, value := range state {
		fmt.Println(key + ": " + value)
	}

	return nil
}

func connectAction(ctx *cli.Context) error {
	if ctx.NArg() != 1 {
		return fmt.Errorf("missing ark URL")
	}

	url := ctx.Args().Get(0)

	_, _, err := common.DecodeUrl(url)
	if err != nil {
		return err
	}

	updateState := map[string]string{
		"ark_url": url,
	}

	if ctx.String("rpc") != "" {
		updateState["rpc_url"] = ctx.String("rpc")
	}

	if err := setState(updateState); err != nil {
		return err
	}

	fmt.Println("Connected to " + url)
	return nil
}
