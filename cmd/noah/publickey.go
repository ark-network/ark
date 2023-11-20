package main

import (
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/urfave/cli/v2"
)

var publicKeyCommand = cli.Command{
	Name:   "publickey",
	Usage:  "Print public key of the Noah wallet",
	Action: publicKeyAction,
}

func publicKeyAction(ctx *cli.Context) error {
	privateKey, err := privateKeyFromPassword()
	if err != nil {
		return err
	}

	publicKey := privateKey.PubKey()
	pubkey, err := common.EncodePubKey(common.MainNet.PubKey, publicKey)
	if err != nil {
		return err
	}

	fmt.Println(pubkey)

	return nil
}
