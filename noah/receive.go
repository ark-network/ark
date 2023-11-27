package main

import (
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/urfave/cli/v2"
)

var receiveCommand = cli.Command{
	Name:   "receive",
	Usage:  "Print the Ark address associated with your wallet and the connected Ark",
	Action: receiveAction,
}

func receiveAction(ctx *cli.Context) error {
	privateKey, err := privateKeyFromPassword()
	if err != nil {
		return err
	}

	publicKey := privateKey.PubKey()

	aspPublicKey, err := getServiceProviderPublicKey()
	if err != nil {
		return err
	}

	addr, err := common.EncodeAddress(common.MainNet.Addr, publicKey, aspPublicKey)
	if err != nil {
		return err
	}

	fmt.Println(addr)

	return nil
}
