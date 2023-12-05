package main

import (
	"context"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/urfave/cli/v2"
)

var (
	roundTxidFlag = &cli.StringFlag{
		Name:  "txid",
		Usage: "the hash of a broadcasted pool transaction",
	}
	currentFlag = &cli.BoolFlag{
		Name:  "current",
		Usage: "info about the status of the ongoing round",
		Value: false,
	}
)

var roundCommand = &cli.Command{
	Name:   "round",
	Usage:  "Get info about an ark round",
	Action: getRoundAction,
	Flags:  []cli.Flag{roundTxidFlag, currentFlag},
}

func getRoundAction(ctx *cli.Context) error {
	client, cleanup, err := getServiceClient()
	if err != nil {
		return err
	}
	defer cleanup()

	txid := ctx.String("txid")
	current := ctx.Bool("current")

	if txid == "" && !current {
		return fmt.Errorf("missing flag, please provide either --txid or --current")
	}

	if current {
		return fmt.Errorf("not supported yet")
	}

	res, err := client.GetRound(context.Background(), &arkv1.GetRoundRequest{Txid: txid})
	if err != nil {
		return err
	}

	printRespJSON(res)
	return nil
}
