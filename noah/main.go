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
)

const (
	DATADIR_ENVVAR = "NOAH_DATADIR"
	STATE_FILE     = "state.json"
	defaultArkURL  = "ark://apub1qgvdtj5ttpuhkldavhq8thtm5auyk0ec4dcmrfdgu0u5hgp9we22v3hrs4x?relays=arelay1qt6f8p7h5f6tm7fv2z5wg92sz92rn9desfhd5733se4lkrptqtdrq65987l-arelay1qt6f8p7h5f6tm7fv2z5wg92sz92rn9desfhd5733se4lkrptqtdrq65987l"
)

var (
	version = "alpha"

	noahDataDirectory = common.AppDataDir("noah", false)
	statePath         = filepath.Join(noahDataDirectory, STATE_FILE)

	initialState = map[string]string{
		"ark_url":               defaultArkURL,
		"encrypted_private_key": "",
		"password_hash":         "",
	}
)

func initCLIEnv() {
	dataDir := cleanAndExpandPath(os.Getenv(DATADIR_ENVVAR))
	if len(dataDir) <= 0 {
		return
	}

	noahDataDirectory = dataDir
	statePath = filepath.Join(noahDataDirectory, STATE_FILE)
}

func main() {
	initCLIEnv()

	app := cli.NewApp()

	app.Version = version
	app.Name = "noah CLI"
	app.Usage = "Command line interface for Ark wallet"
	app.Commands = append(
		app.Commands,
		&balanceCommand,
		&configCommand,
		&initCommand,
		&receiveCommand,
		&redeemCommand,
		&sendCommand,
	)

	app.Before = func(ctx *cli.Context) error {
		if _, err := os.Stat(noahDataDirectory); os.IsNotExist(err) {
			return os.Mkdir(noahDataDirectory, os.ModeDir|0755)
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
