package main

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

var balanceCommand = cli.Command{
	Name:   "balance",
	Usage:  "Print balance of the Noah wallet",
	Action: balanceAction,
}

func balanceAction(ctx *cli.Context) error {
	fmt.Println("balance is not implemented yet")
	return nil
}
