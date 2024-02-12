package main

import (
	"encoding/hex"

	"github.com/urfave/cli/v2"
)

var dumpCommand = cli.Command{
	Name:   "dump-privkey",
	Usage:  "Dump private key of the Ark wallet",
	Action: dumpAction,
}

func dumpAction(ctx *cli.Context) error {
  privateKey, err := privateKeyFromPassword()
	if err != nil {
		return err
	}

	return printJSON(map[string]interface{}{
		"privateKey": hex.EncodeToString(privateKey.Serialize()),
	})
}
