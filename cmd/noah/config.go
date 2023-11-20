package main

import (
	"fmt"

	"github.com/ark-network/ark/common"
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

	if err := setState(map[string]string{"ark_url": url}); err != nil {
		return err
	}

	fmt.Println("Connected to " + url)
	return nil
}

// TODO
func validateURL(url string) error {
	return nil
}
