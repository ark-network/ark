package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/gogo/protobuf/proto"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	DATADIR_ENVVAR = "ARK_CLI_DATADIR"
	STATE_FILE     = "state.json"
)

var (
	version = "alpha"

	datadir   = common.AppDataDir("ark", false)
	statePath = filepath.Join(datadir, STATE_FILE)

	defaultRpcServer = "localhost:6000"
	defaultNoTls     = true

	initialState = map[string]string{
		"rpcserver": defaultRpcServer,
		"no-tls":    strconv.FormatBool(defaultNoTls),
	}
)

func initCLIEnv() {
	dir := cleanAndExpandPath(os.Getenv(DATADIR_ENVVAR))
	if len(dir) <= 0 {
		return
	}
	datadir = dir
	statePath = filepath.Join(dir, STATE_FILE)
}

func main() {
	initCLIEnv()

	app := cli.NewApp()

	app.Version = version
	app.Name = "Ark CLI"
	app.Usage = "Command line interface to interact with arkd"
	app.Commands = append(app.Commands, configCommand, roundCommand)

	app.Before = func(ctx *cli.Context) error {
		if _, err := os.Stat(datadir); os.IsNotExist(err) {
			return os.Mkdir(datadir, os.ModeDir|0755)
		}
		return nil
	}

	if err := app.Run(os.Args); err != nil {
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

func printRespJSON(resp interface{}) {
	jsonMarshaler := &jsonpb.Marshaler{
		EmitDefaults: true,
		OrigName:     true,
		Indent:       "\t", // Matches indentation of printJSON.
	}

	jsonStr, err := jsonMarshaler.MarshalToString(resp.(proto.Message))
	if err != nil {
		fmt.Println("unable to decode response: ", err)
		return
	}

	fmt.Println(jsonStr)
}

func getServiceClient() (arkv1.ArkServiceClient, func(), error) {
	conn, err := getClientConn()
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { conn.Close() }

	return arkv1.NewArkServiceClient(conn), cleanup, nil
}

func getClientConn() (*grpc.ClientConn, error) {
	state, err := getState()
	if err != nil {
		return nil, err
	}
	address, ok := state["rpcserver"]
	if !ok {
		return nil, errors.New("set rpcserver with `config set rpcserver`")
	}

	opts := []grpc.DialOption{grpc.WithDefaultCallOptions()}

	noTls, _ := strconv.ParseBool(state["no-tls"])
	if !noTls {
		return nil, fmt.Errorf("secure connection not supported yet")
	}
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to RPC server: %v",
			err)
	}

	return conn, nil
}
