package main

import (
	"encoding/hex"
	"fmt"

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
	publicKeyBytes := publicKey.SerializeCompressed()

	fmt.Println(hex.EncodeToString(publicKeyBytes))

	return nil
}
