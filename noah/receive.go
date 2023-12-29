package main

import (
	"github.com/urfave/cli/v2"
)

var receiveCommand = cli.Command{
	Name:   "receive",
	Usage:  "Print the Ark address associated with your wallet and the connected Ark",
	Action: receiveAction,
}

func receiveAction(ctx *cli.Context) error {
	offchainAddr, onchainAddr, err := getAddress()
	if err != nil {
		return err
	}
	state, err := getState()
	if err != nil {
		return err
	}
	relays := []string{state["ark_url"]}

	return printJSON(map[string]interface{}{
		"offchain_address": offchainAddr,
		"onchain_address":  onchainAddr,
		"relays":           relays,
	})
}
