package main

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

var (
	recipientFlag = cli.StringFlag{
		Name:     "to",
		Usage:    "recipient ark public key",
		Value:    "",
		Required: true,
	}

	amountFlag = cli.Uint64Flag{
		Name:     "amount",
		Usage:    "amount to send",
		Value:    0,
		Required: true,
	}
)

var sendCommand = cli.Command{
	Name:   "send",
	Usage:  "Send VTXOs to an ark public key",
	Action: sendAction,
}

func sendAction(ctx *cli.Context) error {
	recipient := ctx.String("to")
	amount := ctx.Uint64("amount")

	if len(recipient) <= 0 {
		return cli.Exit("recipient cannot be empty", 1)
	}

	if amount <= 0 {
		return cli.Exit("amount must be greater than 0", 1)
	}

	fmt.Println("send command is not implemented yet")

	return nil
}
