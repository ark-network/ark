package main

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

var (
	amountOnboardFlag = cli.Uint64Flag{
		Name:     "amount",
		Usage:    "amount to onboard in sats",
		Required: true,
	}
)

var onboardCommand = cli.Command{
	Name:   "onboard",
	Usage:  "onboard VTXOs to the Ark network",
	Action: onboardAction,
	Flags:  []cli.Flag{&amountOnboardFlag},
}

func onboardAction(ctx *cli.Context) error {
	amount := ctx.Uint64("amount")

	if amount <= 0 {
		return fmt.Errorf("missing amount flag (--amount)")
	}

	// (1) use craftCongestionTree -> treeFactory, treeOutputScript
	// (2) sendOnchain to the script built from by (1)
	// (3) use tree factory to build the congestion tree

	return nil
}
