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
	Flags:  []cli.Flag{&recipientFlag, &amountFlag},
}

func sendAction(ctx *cli.Context) error {
	recipient := ctx.String("to")
	amount := ctx.Uint64("amount")

	if len(recipient) <= 0 {
		return fmt.Errorf("missing recipient flag (--to)")
	}

	if amount <= 0 {
		return fmt.Errorf("missing amount flag (--amount)")
	}

	fmt.Println("send command is not implemented yet")

	return nil
}
