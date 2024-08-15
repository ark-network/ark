package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/ark-network/ark/client/covenant"
	"github.com/ark-network/ark/client/covenantless"
	"github.com/ark-network/ark/client/flags"
	"github.com/ark-network/ark/client/interfaces"
	"github.com/ark-network/ark/client/utils"
	"github.com/ark-network/ark/common"
	"github.com/urfave/cli/v2"
)

var version = "alpha"

var (
	balanceCommand = cli.Command{
		Name:  "balance",
		Usage: "Shows the onchain and offchain balance of the Ark wallet",
		Action: func(ctx *cli.Context) error {
			cli, err := getCLIFromState(ctx)
			if err != nil {
				return err
			}
			return cli.Balance(ctx)
		},
		Flags: []cli.Flag{&flags.ExpiryDetailsFlag},
	}

	configCommand = cli.Command{
		Name:  "config",
		Usage: "Shows configuration of the Ark wallet",
		Action: func(ctx *cli.Context) error {
			state, err := utils.GetState(ctx)
			if err != nil {
				return err
			}

			return utils.PrintJSON(state)
		},
	}

	dumpCommand = cli.Command{
		Name:  "dump-privkey",
		Usage: "Dumps private key of the Ark wallet",
		Action: func(ctx *cli.Context) error {
			privKey, err := utils.PrivateKeyFromPassword(ctx)
			if err != nil {
				return err
			}

			return utils.PrintJSON(map[string]interface{}{
				"private_key": hex.EncodeToString(privKey.Serialize()),
			})
		},
		Flags: []cli.Flag{&flags.PasswordFlag},
	}

	initCommand = cli.Command{
		Name:  "init",
		Usage: "Initialize your Ark wallet with an encryption password, and connect it to an ASP",
		Action: func(ctx *cli.Context) error {
			cli, err := getCLIFromFlags(ctx)
			if err != nil {
				return err
			}

			return cli.Init(ctx)
		},
		Flags: []cli.Flag{&flags.PasswordFlag, &flags.PrivateKeyFlag, &flags.NetworkFlag, &flags.UrlFlag, &flags.ExplorerFlag},
	}

	onboardCommand = cli.Command{
		Name:  "onboard",
		Usage: "Onboard the Ark by lifting your funds",
		Action: func(ctx *cli.Context) error {
			cli, err := getCLIFromState(ctx)
			if err != nil {
				return err
			}
			return cli.Onboard(ctx)
		},
		Flags: []cli.Flag{&flags.AmountOnboardFlag, &flags.PasswordFlag},
	}

	sendCommand = cli.Command{
		Name:  "send",
		Usage: "Send your onchain or offchain funds to one or many receivers",
		Action: func(ctx *cli.Context) error {
			state, err := utils.GetState(ctx)
			if err != nil {
				return err
			}

			networkName := state[utils.NETWORK]
			cli, err := getCLI(networkName)
			if err != nil {
				return err
			}
			if strings.Contains(networkName, "liquid") {
				return cli.Send(ctx)
			}
			return cli.SendAsync(ctx)
		},
		Flags: []cli.Flag{&flags.ReceiversFlag, &flags.ToFlag, &flags.AmountFlag, &flags.PasswordFlag, &flags.EnableExpiryCoinselectFlag, &flags.AsyncPaymentFlag},
	}

	claimCommand = cli.Command{
		Name:  "claim",
		Usage: "Join round to claim pending payments",
		Action: func(ctx *cli.Context) error {
			cli, err := getCLIFromState(ctx)
			if err != nil {
				return err
			}
			return cli.ClaimAsync(ctx)
		},
		Flags: []cli.Flag{&flags.PasswordFlag},
	}

	receiveCommand = cli.Command{
		Name:  "receive",
		Usage: "Shows both onchain and offchain addresses",
		Action: func(ctx *cli.Context) error {
			cli, err := getCLIFromState(ctx)
			if err != nil {
				return err
			}

			return cli.Receive(ctx)
		},
	}

	redeemCommand = cli.Command{
		Name:  "redeem",
		Usage: "Redeem your offchain funds, either collaboratively or unilaterally",
		Flags: []cli.Flag{&flags.AddressFlag, &flags.AmountToRedeemFlag, &flags.ForceFlag, &flags.PasswordFlag, &flags.EnableExpiryCoinselectFlag},
		Action: func(ctx *cli.Context) error {
			cli, err := getCLIFromState(ctx)
			if err != nil {
				return err
			}
			return cli.Redeem(ctx)
		},
	}
)

func main() {
	app := cli.NewApp()

	app.Version = version
	app.Name = "Ark CLI"
	app.Usage = "ark wallet command line interface"
	app.Commands = append(
		app.Commands,
		&balanceCommand,
		&configCommand,
		&dumpCommand,
		&initCommand,
		&receiveCommand,
		&redeemCommand,
		&sendCommand,
		&claimCommand,
		&onboardCommand,
	)
	app.Flags = []cli.Flag{
		flags.DatadirFlag,
	}

	app.Before = func(ctx *cli.Context) error {
		datadir := cleanAndExpandPath(ctx.String("datadir"))

		if err := ctx.Set("datadir", datadir); err != nil {
			return err
		}

		if _, err := os.Stat(datadir); os.IsNotExist(err) {
			return os.Mkdir(datadir, os.ModeDir|0755)
		}
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(fmt.Errorf("error: %v", err))
		os.Exit(1)
	}
}

func getCLIFromState(ctx *cli.Context) (interfaces.CLI, error) {
	state, err := utils.GetState(ctx)
	if err != nil {
		return nil, err
	}

	networkName := state[utils.NETWORK]
	return getCLI(networkName)
}

func getCLIFromFlags(ctx *cli.Context) (interfaces.CLI, error) {
	networkName := strings.ToLower(ctx.String("network"))
	return getCLI(networkName)
}

func getCLI(networkName string) (interfaces.CLI, error) {
	switch networkName {
	case common.Liquid.Name, common.LiquidTestNet.Name, common.LiquidRegTest.Name:
		return covenant.New(), nil
	case common.Bitcoin.Name, common.BitcoinTestNet.Name, common.BitcoinRegTest.Name, common.BitcoinSigNet.Name:
		return covenantless.New(), nil
	default:
		return nil, fmt.Errorf("unknown network (%s)", networkName)
	}
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func cleanAndExpandPath(path string) string {
	if path == "" {
		return ""
	}

	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		var homeDir string
		u, err := user.Current()
		if err == nil {
			homeDir = u.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}
