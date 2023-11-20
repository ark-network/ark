package main

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

var (
	defaultArkURL = "localhost:9000"
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
		return cli.Exit("connect <ARK_URL>", 1)
	}

	arg := ctx.Args().Get(0)
	if err := validateURL(arg); err != nil {
		return cli.Exit(err, 1)
	}

	if err := setState(map[string]string{"ark_url": arg}); err != nil {
		return cli.Exit(err, 1)
	}

	fmt.Println("Connected to " + arg)
	return nil
}

// TODO
func validateURL(url string) error {
	return nil
}
