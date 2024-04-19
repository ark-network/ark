package main

import (
	"encoding/hex"

	"github.com/urfave/cli/v2"
)

var dumpCommand = cli.Command{
	Name:   "dump-privkey",
	Usage:  "Dumps private key of the Ark wallet",
	Action: dumpAction,
	Flags:  []cli.Flag{&passwordFlag},
}

func dumpAction(ctx *cli.Context) error {
	privateKey, err := privateKeyFromPassword(ctx)
	if err != nil {
		return err
	}

	return printJSON(map[string]interface{}{
		"private_key": hex.EncodeToString(privateKey.Serialize()),
	})
}
