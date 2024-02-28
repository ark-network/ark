package main

import (
	"github.com/urfave/cli/v2"
)

var receiveCommand = cli.Command{
	Name:   "receive",
	Usage:  "Shows both onchain and offchain addresses",
	Action: receiveAction,
}

func receiveAction(ctx *cli.Context) error {
	offchainAddr, onchainAddr, _, err := getAddress()
	if err != nil {
		return err
	}

	return printJSON(map[string]interface{}{
		"offchain_address": offchainAddr,
		"onchain_address":  onchainAddr,
	})
}
