package main

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

var receiveCommand = cli.Command{
	Name:   "receive",
	Usage:  "Print the Ark address associated with your wallet and the connected Ark",
	Action: receiveAction,
}

func receiveAction(ctx *cli.Context) error {
	addr, err := getAddress()
	if err != nil {
		return err
	}

	fmt.Println(addr)

	return nil
}
