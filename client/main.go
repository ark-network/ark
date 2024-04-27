package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/ark-network/ark/common"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/network"
)

const (
	DATADIR_ENVVAR = "ARK_WALLET_DATADIR"
	STATE_FILE     = "state.json"
	defaultNetwork = "liquid"

	ASP_URL               = "asp_url"
	ASP_PUBKEY            = "asp_public_key"
	ROUND_LIFETIME        = "round_lifetime"
	UNILATERAL_EXIT_DELAY = "unilateral_exit_delay"
	ENCRYPTED_PRVKEY      = "encrypted_private_key"
	PASSWORD_HASH         = "password_hash"
	PUBKEY                = "public_key"
	NETWORK               = "network"
	EXPLORER              = "explorer"
)

var (
	version = "alpha"

	datadir     = common.AppDataDir("ark-cli", false)
	statePath   = filepath.Join(datadir, STATE_FILE)
	explorerUrl = map[string]string{
		network.Liquid.Name:  "https://blockstream.info/liquid/api",
		network.Testnet.Name: "https://blockstream.info/liquidtestnet/api",
		network.Regtest.Name: "http://localhost:3001",
	}

	initialState = map[string]string{
		ASP_URL:               "",
		ASP_PUBKEY:            "",
		ROUND_LIFETIME:        "",
		UNILATERAL_EXIT_DELAY: "",
		ENCRYPTED_PRVKEY:      "",
		PASSWORD_HASH:         "",
		PUBKEY:                "",
		NETWORK:               defaultNetwork,
	}
)

func initCLIEnv() {
	dir := cleanAndExpandPath(os.Getenv(DATADIR_ENVVAR))
	if len(dir) <= 0 {
		return
	}

	datadir = dir
	statePath = filepath.Join(datadir, STATE_FILE)
}

func main() {
	initCLIEnv()

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
		&onboardCommand,
	)

	app.Before = func(ctx *cli.Context) error {
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

func getState() (map[string]string, error) {
	file, err := os.ReadFile(statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := setInitialState(); err != nil {
			return nil, err
		}
		return initialState, nil
	}

	data := map[string]string{}
	if err := json.Unmarshal(file, &data); err != nil {
		return nil, err
	}

	return data, nil
}

func setInitialState() error {
	jsonString, err := json.Marshal(initialState)
	if err != nil {
		return err
	}
	return os.WriteFile(statePath, jsonString, 0755)
}

func setState(data map[string]string) error {
	currentData, err := getState()
	if err != nil {
		return err
	}

	mergedData := merge(currentData, data)

	jsonString, err := json.Marshal(mergedData)
	if err != nil {
		return err
	}
	err = os.WriteFile(statePath, jsonString, 0755)
	if err != nil {
		return fmt.Errorf("writing to file: %w", err)
	}

	return nil
}

func merge(maps ...map[string]string) map[string]string {
	merge := make(map[string]string, 0)
	for _, m := range maps {
		for k, v := range m {
			merge[k] = v
		}
	}
	return merge
}
