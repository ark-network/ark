package main

import (
	"github.com/urfave/cli/v2"
)

var configCommand = cli.Command{
	Name:   "config",
	Usage:  "Print local configuration of the Noah CLI",
	Action: printConfigAction,
}

func printConfigAction(ctx *cli.Context) error {
	state, err := getState()
	if err != nil {
		return err
	}

	return printJSON(state)
}
