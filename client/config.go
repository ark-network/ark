package main

import (
	"github.com/urfave/cli/v2"
)

var configCommand = cli.Command{
	Name:   "config",
	Usage:  "Shows configuration of the Ark wallet",
	Action: printConfigAction,
}

func printConfigAction(ctx *cli.Context) error {
	state, err := getState()
	if err != nil {
		return err
	}

	return printJSON(state)
}
