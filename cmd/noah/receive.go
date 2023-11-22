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
	pubkey, err := common.EncodePubKey(common.MainNet.PubKey, publicKey)
	if err != nil {
		return err
	}

	// todo: fetch asp public key from ark
	fmt.Println("Ark address not implemented yet: printing pubkey instead")
	fmt.Println(pubkey)

	return nil
}
