package main

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

var (
	addressFlag = cli.StringFlag{
		Name:     "address",
		Usage:    "main chain address receiving the redeeemed VTXO",
		Value:    "",
		Required: true,
	}

	amountToRedeemFlag = cli.Uint64Flag{
		Name:     "amount",
		Usage:    "amount to redeem",
		Value:    0,
		Required: true,
	}

	forceFlag = cli.BoolFlag{
		Name:     "force",
		Usage:    "force redemption without collaborate with the Ark service provider",
		Value:    false,
		Required: false,
	}
)

var redeemCommand = cli.Command{
	Name:   "redeem",
	Usage:  "Redeem VTXO(s)",
	Flags:  []cli.Flag{&addressFlag, &amountToRedeemFlag, &forceFlag},
	Action: redeemAction,
}

func redeemAction(ctx *cli.Context) error {
	address := ctx.String("address")
	amount := ctx.Uint64("amount")
	force := ctx.Bool("force")

	if len(address) <= 0 {
		return cli.Exit("address cannot be empty", 1)
	}

	if amount <= 0 {
		return cli.Exit("amount must be greater than 0", 1)
	}

	if force {
		return unilateralRedeem(address, amount)
	}

	return collaborativeRedeem(address, amount)
}

func collaborativeRedeem(address string, amount uint64) error {
	fmt.Println("collaborative redeem is not implemented yet")
	return nil
}

func unilateralRedeem(address string, amount uint64) error {
	fmt.Println("unilateral redeem is not implemented yet")
	return nil
}
