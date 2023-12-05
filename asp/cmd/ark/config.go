package main

import (
	"fmt"
	"strconv"

	"github.com/urfave/cli/v2"
)

var (
	rpcServerFlag = &cli.StringFlag{
		Name:  "rpcserver",
		Usage: "the addr of the arkd to connect to in the form <host>:<port>",
		Value: defaultRpcServer,
	}
	noTlsFlag = &cli.BoolFlag{
		Name:  "no-tls",
		Usage: "used to disable TLS termination",
		Value: false,
	}
)

var configCommand = &cli.Command{
	Name:   "config",
	Usage:  "Print local configuration of the ark CLI",
	Action: printConfigAction,
	Subcommands: []*cli.Command{
		{
			Name:   "init",
			Usage:  "initialize the CLI state with flags",
			Action: configInitAction,
			Flags:  []cli.Flag{rpcServerFlag, noTlsFlag},
		},
		{
			Name:   "set",
			Usage:  "set a <key> <value> in the local state",
			Action: configSetAction,
		},
	},
}

func printConfigAction(ctx *cli.Context) error {
	state, err := getState()
	if err != nil {
		return err
	}

	for key, value := range state {
		fmt.Println(key + ": " + value)
	}

	return nil
}

func configInitAction(ctx *cli.Context) error {
	return setState(map[string]string{
		"rpcserver": ctx.String("rpcserver"),
		"no-tls":    strconv.FormatBool(ctx.Bool("no-tls")),
	})
}

func configSetAction(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("key and/or value are missing")
	}

	key := c.Args().Get(0)
	value := c.Args().Get(1)

	if value == "" {
		return fmt.Errorf("value must not be an empty string")
	}

	if err := setState(map[string]string{key: value}); err != nil {
		return err
	}

	fmt.Printf("%s %s has been set\n", key, value)

	return nil
}
