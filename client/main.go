package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/ark-network/ark/common"
	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

const (
	DatadirEnvVar = "ARK_WALLET_DATADIR"
)

var (
	Version      string
	arkSdkClient arksdk.ArkClient
)

func main() {
	app := cli.NewApp()
	app.Version = Version
	app.Name = "Ark CLI"
	app.Usage = "ark wallet command line interface"
	app.Commands = append(
		app.Commands,
		&initCommand,
		&configCommand,
		&dumpCommand,
		&receiveCommand,
		&settleCmd,
		&sendCommand,
		&balanceCommand,
		&redeemCommand,
		&notesCommand,
		&registerNostrCommand,
	)
	app.Flags = []cli.Flag{
		datadirFlag,
		networkFlag,
	}
	app.Before = func(ctx *cli.Context) error {
		sdk, err := getArkSdkClient(ctx)
		if err != nil {
			return fmt.Errorf("error initializing ark sdk client: %v", err)
		}
		arkSdkClient = sdk

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(fmt.Errorf("error: %v", err))
		os.Exit(1)
	}
}

var (
	datadirFlag = &cli.StringFlag{
		Name:     "datadir",
		Usage:    "Specify the data directory",
		Required: false,
		Value:    common.AppDataDir("ark-cli", false),
		EnvVars:  []string{DatadirEnvVar},
	}
	networkFlag = &cli.StringFlag{
		Name:  "network",
		Usage: "network to use liquid, testnet, regtest, signet for bitcoin, or liquid, liquidtestnet, liquidregtest for liquid)",
		Value: "liquid",
	}
	explorerFlag = &cli.StringFlag{
		Name:  "explorer",
		Usage: "the url of the explorer to use",
	}
	passwordFlag = &cli.StringFlag{
		Name:  "password",
		Usage: "password to unlock the wallet",
	}
	expiryDetailsFlag = &cli.BoolFlag{
		Name:  "compute-expiry-details",
		Usage: "compute client-side VTXOs expiry time",
	}
	privateKeyFlag = &cli.StringFlag{
		Name:  "prvkey",
		Usage: "optional private key to encrypt",
	}
	urlFlag = &cli.StringFlag{
		Name:     "server-url",
		Usage:    "the url of the Ark server to connect to",
		Required: true,
	}
	receiversFlag = &cli.StringFlag{
		Name:  "receivers",
		Usage: "JSON encoded receivers of the send transaction",
	}
	toFlag = &cli.StringFlag{
		Name:  "to",
		Usage: "recipient address",
	}
	amountFlag = &cli.Uint64Flag{
		Name:  "amount",
		Usage: "amount to send in sats",
	}
	zeroFeesFlag = &cli.BoolFlag{
		Name:    "zero-fees",
		Aliases: []string{"z"},
		Usage:   "UNSAFE: allow sending offchain transactions with zero fees, disable unilateral exit",
		Value:   false,
	}
	enableExpiryCoinselectFlag = &cli.BoolFlag{
		Name:  "enable-expiry-coinselect",
		Usage: "select VTXOs about to expire first",
	}
	addressFlag = &cli.StringFlag{
		Name:  "address",
		Usage: "main chain address receiving the redeemed VTXO",
	}
	amountToRedeemFlag = &cli.Uint64Flag{
		Name:  "amount",
		Usage: "amount to redeem",
	}
	forceFlag = &cli.BoolFlag{
		Name:  "force",
		Usage: "force redemption without collaboration",
	}
	notesFlag = &cli.StringSliceFlag{
		Name:    "notes",
		Aliases: []string{"n"},
		Usage:   "notes to redeem",
	}
	nostrProfileFlag = &cli.StringFlag{
		Name:    "profile",
		Aliases: []string{"p"},
		Usage:   "nostr profile to register",
	}
	restFlag = &cli.BoolFlag{
		Name:        "rest",
		Usage:       "use REST client instead of gRPC",
		Value:       false,
		DefaultText: "false",
	}
)

var (
	initCommand = cli.Command{
		Name:  "init",
		Usage: "Initialize Ark wallet with encryption password, connect to Ark server",
		Action: func(ctx *cli.Context) error {
			return initArkSdk(ctx)
		},
		Flags: []cli.Flag{networkFlag, passwordFlag, privateKeyFlag, urlFlag, explorerFlag, restFlag},
	}
	configCommand = cli.Command{
		Name:  "config",
		Usage: "Shows Ark wallet configuration",
		Action: func(ctx *cli.Context) error {
			return config(ctx)
		},
	}
	dumpCommand = cli.Command{
		Name:  "dump-privkey",
		Usage: "Dumps private key of the Ark wallet",
		Action: func(ctx *cli.Context) error {
			return dumpPrivKey(ctx)
		},
		Flags: []cli.Flag{passwordFlag},
	}
	receiveCommand = cli.Command{
		Name:  "receive",
		Usage: "Shows boarding and offchain addresses",
		Action: func(ctx *cli.Context) error {
			return receive(ctx)
		},
	}
	settleCmd = cli.Command{
		Name:  "settle",
		Usage: "Settle onboarding or pending funds",
		Action: func(ctx *cli.Context) error {
			return settle(ctx)
		},
		Flags: []cli.Flag{passwordFlag},
	}
	balanceCommand = cli.Command{
		Name:  "balance",
		Usage: "Shows onchain and offchain Ark wallet balance",
		Action: func(ctx *cli.Context) error {
			return balance(ctx)
		},
		Flags: []cli.Flag{expiryDetailsFlag},
	}
	sendCommand = cli.Command{
		Name:  "send",
		Usage: "Send funds offchain",
		Action: func(ctx *cli.Context) error {
			return send(ctx)
		},
		Flags: []cli.Flag{receiversFlag, toFlag, amountFlag, enableExpiryCoinselectFlag, passwordFlag, zeroFeesFlag},
	}
	redeemCommand = cli.Command{
		Name:  "redeem",
		Usage: "Redeem offchain funds, collaboratively or unilaterally",
		Flags: []cli.Flag{addressFlag, amountToRedeemFlag, forceFlag, passwordFlag},
		Action: func(ctx *cli.Context) error {
			return redeem(ctx)
		},
	}
	notesCommand = cli.Command{
		Name:  "redeem-notes",
		Usage: "Redeem offchain notes",
		Flags: []cli.Flag{notesFlag, passwordFlag},
		Action: func(ctx *cli.Context) error {
			return redeemNotes(ctx)
		},
	}
	registerNostrCommand = cli.Command{
		Name:  "register-nostr",
		Usage: "Register Nostr profile",
		Flags: []cli.Flag{nostrProfileFlag, passwordFlag},
		Action: func(ctx *cli.Context) error {
			return registerNostrProfile(ctx)
		},
	}
)

func initArkSdk(ctx *cli.Context) error {
	password, err := readPassword(ctx)
	if err != nil {
		return err
	}

	clientType := arksdk.GrpcClient
	if ctx.Bool(restFlag.Name) {
		clientType = arksdk.RestClient
	}

	return arkSdkClient.Init(
		ctx.Context, arksdk.InitArgs{
			ClientType:  clientType,
			WalletType:  arksdk.SingleKeyWallet,
			ServerUrl:   ctx.String(urlFlag.Name),
			Seed:        ctx.String(privateKeyFlag.Name),
			Password:    string(password),
			ExplorerURL: ctx.String(explorerFlag.Name),
		},
	)
}

func config(ctx *cli.Context) error {
	cfgData, err := arkSdkClient.GetConfigData(ctx.Context)
	if err != nil {
		return err
	}

	cfg := map[string]interface{}{
		"server_url":                   cfgData.ServerUrl,
		"server_pubkey":                hex.EncodeToString(cfgData.ServerPubKey.SerializeCompressed()),
		"wallet_type":                  cfgData.WalletType,
		"client_tyep":                  cfgData.ClientType,
		"network":                      cfgData.Network.Name,
		"vtxo_tree_expiry":             cfgData.VtxoTreeExpiry,
		"unilateral_exit_delay":        cfgData.UnilateralExitDelay,
		"dust":                         cfgData.Dust,
		"boarding_descriptor_template": cfgData.BoardingDescriptorTemplate,
		"explorer_url":                 cfgData.ExplorerURL,
		"forfeit_address":              cfgData.ForfeitAddress,
		"with_transaction_feed":        cfgData.WithTransactionFeed,
	}

	return printJSON(cfg)
}

func dumpPrivKey(ctx *cli.Context) error {
	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	privateKey, err := arkSdkClient.Dump(ctx.Context)
	if err != nil {
		return err
	}

	return printJSON(map[string]interface{}{
		"private_key": privateKey,
	})
}

func receive(ctx *cli.Context) error {
	offchainAddr, boardingAddr, err := arkSdkClient.Receive(ctx.Context)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{
		"boarding_address": boardingAddr,
		"offchain_address": offchainAddr,
	})
}

func settle(ctx *cli.Context) error {
	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	txID, err := arkSdkClient.Settle(ctx.Context)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{
		"txid": txID,
	})
}

func send(ctx *cli.Context) error {
	receiversJSON := ctx.String(receiversFlag.Name)
	to := ctx.String(toFlag.Name)
	amount := ctx.Uint64(amountFlag.Name)
	zeroFees := ctx.Bool(zeroFeesFlag.Name)
	if receiversJSON == "" && to == "" && amount == 0 {
		return fmt.Errorf("missing destination, use --to and --amount or --receivers")
	}

	configData, err := arkSdkClient.GetConfigData(ctx.Context)
	if err != nil {
		return err
	}

	net, err := getNetwork(ctx, configData)
	if err != nil {
		return err
	}

	isBitcoin := isBtcChain(net)

	var receivers []arksdk.Receiver
	if receiversJSON != "" {
		receivers, err = parseReceivers(receiversJSON, isBitcoin)
		if err != nil {
			return err
		}
	} else {
		if isBitcoin {
			receivers = []arksdk.Receiver{arksdk.NewBitcoinReceiver(to, amount)}
		} else {
			receivers = []arksdk.Receiver{arksdk.NewLiquidReceiver(to, amount)}
		}
	}

	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	if isBitcoin {
		return sendCovenantLess(ctx, receivers, zeroFees)
	}
	return sendCovenant(ctx, receivers)
}

func balance(ctx *cli.Context) error {
	computeExpiration := ctx.Bool(expiryDetailsFlag.Name)
	bal, err := arkSdkClient.Balance(ctx.Context, computeExpiration)
	if err != nil {
		return err
	}
	return printJSON(bal)
}

func redeem(ctx *cli.Context) error {
	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	force := ctx.Bool(forceFlag.Name)
	address := ctx.String(addressFlag.Name)
	amount := ctx.Uint64(amountToRedeemFlag.Name)
	computeExpiration := ctx.Bool(expiryDetailsFlag.Name)
	if force {
		err := arkSdkClient.UnilateralRedeem(ctx.Context)
		if err != nil {
			return err
		}
		return nil
	}

	txID, err := arkSdkClient.CollaborativeRedeem(
		ctx.Context, address, amount, computeExpiration,
	)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{
		"txid": txID,
	})
}

func registerNostrProfile(ctx *cli.Context) error {
	profile := ctx.String(nostrProfileFlag.Name)

	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	return arkSdkClient.SetNostrNotificationRecipient(ctx.Context, profile)
}

func redeemNotes(ctx *cli.Context) error {
	notes := ctx.StringSlice(notesFlag.Name)

	password, err := readPassword(ctx)
	if err != nil {
		return err
	}
	if err := arkSdkClient.Unlock(ctx.Context, string(password)); err != nil {
		return err
	}

	txID, err := arkSdkClient.RedeemNotes(ctx.Context, notes)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{
		"txid": txID,
	})
}

func getArkSdkClient(ctx *cli.Context) (arksdk.ArkClient, error) {
	dataDir := ctx.String(datadirFlag.Name)
	sdkRepository, err := store.NewStore(store.Config{
		ConfigStoreType: types.FileStore,
		BaseDir:         dataDir,
	})
	if err != nil {
		return nil, err
	}

	cfgData, err := sdkRepository.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}

	commandName := ctx.Args().First()
	if commandName != "init" && cfgData == nil {
		return nil, fmt.Errorf("CLI not initialized, run 'init' cmd to initialize")
	}

	net, err := getNetwork(ctx, cfgData)
	if err != nil {
		return nil, err
	}

	if isBtcChain(net) {
		return loadOrCreateClient(
			arksdk.LoadCovenantlessClient, arksdk.NewCovenantlessClient, sdkRepository,
		)
	}
	return loadOrCreateClient(
		arksdk.LoadCovenantClient, arksdk.NewCovenantClient, sdkRepository,
	)
}

func loadOrCreateClient(
	loadFunc, newFunc func(types.Store) (arksdk.ArkClient, error),
	sdkRepository types.Store,
) (arksdk.ArkClient, error) {
	client, err := loadFunc(sdkRepository)
	if err != nil {
		if errors.Is(err, arksdk.ErrNotInitialized) {
			return newFunc(sdkRepository)
		}
		return nil, err
	}
	return client, err
}

func getNetwork(ctx *cli.Context, cfgData *types.Config) (string, error) {
	if cfgData == nil {
		return ctx.String(networkFlag.Name), nil
	}

	return cfgData.Network.Name, nil
}

func isBtcChain(network string) bool {
	return network == common.Bitcoin.Name ||
		network == common.BitcoinTestNet.Name ||
		network == common.BitcoinTestNet4.Name ||
		network == common.BitcoinSigNet.Name ||
		network == common.BitcoinMutinyNet.Name ||
		network == common.BitcoinRegTest.Name
}

func parseReceivers(receveirsJSON string, isBitcoin bool) ([]arksdk.Receiver, error) {
	list := make([]map[string]interface{}, 0)
	if err := json.Unmarshal([]byte(receveirsJSON), &list); err != nil {
		return nil, err
	}
	receivers := make([]arksdk.Receiver, 0, len(list))
	if isBitcoin {
		for _, v := range list {
			receivers = append(receivers, arksdk.NewBitcoinReceiver(
				v["to"].(string), uint64(v["amount"].(float64)),
			))
		}
		return receivers, nil
	}

	for _, v := range list {
		receivers = append(receivers, arksdk.NewLiquidReceiver(
			v["to"].(string), uint64(v["amount"].(float64)),
		))
	}
	return receivers, nil
}

func sendCovenantLess(ctx *cli.Context, receivers []arksdk.Receiver, withZeroFees bool) error {
	var onchainReceivers, offchainReceivers []arksdk.Receiver

	for _, receiver := range receivers {
		if receiver.IsOnchain() {
			onchainReceivers = append(onchainReceivers, receiver)
		} else {
			offchainReceivers = append(offchainReceivers, receiver)
		}
	}

	if len(onchainReceivers) > 0 {
		txid, err := arkSdkClient.SendOnChain(ctx.Context, onchainReceivers)
		if err != nil {
			return err
		}
		return printJSON(map[string]interface{}{"txid": txid})
	}

	computeExpiration := ctx.Bool(enableExpiryCoinselectFlag.Name)
	redeemTx, err := arkSdkClient.SendOffChain(
		ctx.Context, computeExpiration, offchainReceivers, withZeroFees,
	)
	if err != nil {
		return err
	}
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(redeemTx), true)
	if err != nil {
		fmt.Println("WARN: failed to parse the redeem tx, returning the full psbt")
		return printJSON(map[string]string{"redeem_tx": redeemTx})
	}
	return printJSON(map[string]string{"txid": ptx.UnsignedTx.TxHash().String()})
}

func sendCovenant(ctx *cli.Context, receivers []arksdk.Receiver) error {
	var onchainReceivers, offchainReceivers []arksdk.Receiver

	for _, receiver := range receivers {
		if receiver.IsOnchain() {
			onchainReceivers = append(onchainReceivers, receiver)
		} else {
			offchainReceivers = append(offchainReceivers, receiver)
		}
	}

	if len(onchainReceivers) > 0 {
		txID, err := arkSdkClient.SendOnChain(ctx.Context, onchainReceivers)
		if err != nil {
			return err
		}
		return printJSON(map[string]interface{}{"txid": txID})
	}

	computeExpiration := ctx.Bool(enableExpiryCoinselectFlag.Name)
	txid, err := arkSdkClient.SendOffChain(
		ctx.Context, computeExpiration, offchainReceivers, false,
	)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{"txid": txid})
}

func readPassword(ctx *cli.Context) ([]byte, error) {
	password := []byte(ctx.String("password"))
	if len(password) == 0 {
		fmt.Print("unlock your wallet with password: ")
		var err error
		password, err = term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return nil, err
		}
	}
	return password, nil
}

func printJSON(resp interface{}) error {
	jsonBytes, err := json.MarshalIndent(resp, "", "\t")
	if err != nil {
		return err
	}
	fmt.Println(string(jsonBytes))
	return nil
}
