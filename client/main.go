package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	filestore "github.com/ark-network/ark/pkg/client-sdk/store/file"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

const (
	DatadirEnvVar   = "ARK_WALLET_DATADIR"
	scryptKeyLength = 1048576
)

var (
	version      = "alpha"
	arkSdkClient arksdk.ArkClient
)

func main() {
	app := cli.NewApp()
	app.Version = version
	app.Name = "Ark CLI"
	app.Usage = "ark wallet command line interface"
	app.Commands = append(
		app.Commands,
		&initCommand,
		&configCommand,
		&dumpCommand,
		&receiveCommand,
		&claimCmd,
		&sendCommand,
		&balanceCommand,
		&redeemCommand,
	)
	app.Flags = []cli.Flag{
		datadirFlag,
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
		Name:     "ark-url",
		Usage:    "the url of the ASP to connect to",
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
)

var (
	initCommand = cli.Command{
		Name:  "init",
		Usage: "Initialize Ark wallet with encryption password, connect to ASP",
		Action: func(ctx *cli.Context) error {
			return initArkSdk(ctx)
		},
		Flags: []cli.Flag{passwordFlag, privateKeyFlag, urlFlag},
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
	claimCmd = cli.Command{
		Name:  "claim",
		Usage: "Claim onboarding funds or pending payments",
		Action: func(ctx *cli.Context) error {
			return claim(ctx)
		},
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
		Usage: "Send funds onchain, offchain, or asynchronously",
		Action: func(ctx *cli.Context) error {
			return send(ctx)
		},
		Flags: []cli.Flag{receiversFlag, toFlag, amountFlag, enableExpiryCoinselectFlag},
	}
	redeemCommand = cli.Command{
		Name:  "redeem",
		Usage: "Redeem offchain funds, collaboratively or unilaterally",
		Flags: []cli.Flag{addressFlag, amountToRedeemFlag, forceFlag},
		Action: func(ctx *cli.Context) error {
			return redeem(ctx)
		},
	}
)

func initArkSdk(ctx *cli.Context) error {
	password, err := readPassword(ctx)
	if err != nil {
		return err
	}

	return arkSdkClient.Init(
		context.Background(),
		arksdk.InitArgs{
			ClientType: arksdk.GrpcClient,
			WalletType: arksdk.SingleKeyWallet,
			AspUrl:     ctx.String(urlFlag.Name),
			Seed:       ctx.String(privateKeyFlag.Name),
			Password:   string(password),
		},
	)
}

func config(ctx *cli.Context) error {
	cfgStore, err := getConfigStore(ctx.String(datadirFlag.Name))
	if err != nil {
		return err
	}
	cfgData, err := cfgStore.GetData(context.Background())
	if err != nil {
		return err
	}
	return printJSON(cfgData)
}

func dumpPrivKey(ctx *cli.Context) error {
	password, err := readPassword(ctx)
	if err != nil {
		return err
	}

	walletStore, err := arkSdkClient.GetWalletStore(
		context.Background(),
		string(password),
	)
	if err != nil {
		return err
	}

	walletData, err := walletStore.GetWallet()
	if err != nil {
		return err
	}

	privateKeyBytes, err := decrypt(walletData.EncryptedPrvkey, password)
	if err != nil {
		return err
	}

	privateKey := secp256k1.PrivKeyFromBytes(privateKeyBytes)
	return printJSON(map[string]interface{}{
		"private_key": hex.EncodeToString(privateKey.Serialize()),
	})
}

func receive(ctx *cli.Context) error {
	offchainAddr, boardingAddr, err := arkSdkClient.Receive(context.Background())
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{
		"offchain_address": offchainAddr,
		"boarding_address": boardingAddr,
	})
}

func claim(ctx *cli.Context) error {
	txID, err := arkSdkClient.Claim(context.Background())
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{
		"txid": txID,
	})
}

func send(ctx *cli.Context) error {
	rcvrs, to, amount := ctx.String(receiversFlag.Name), ctx.String(toFlag.Name), ctx.Uint64(amountFlag.Name)

	if rcvrs == "" && to == "" && amount == 0 {
		return fmt.Errorf("missing destination, use --to and --amount or --receivers")
	}

	configStore, err := getConfigStore(ctx.String(datadirFlag.Name))
	if err != nil {
		return err
	}

	cfgData, err := configStore.GetData(context.Background())
	if err != nil {
		return err
	}

	net := getNetwork(ctx, cfgData)
	isBitcoin, isLiquid := isBtcChain(net), isLiquidChain(net)

	var receivers []arksdk.Receiver
	if isBitcoin || isLiquid {
		if rcvrs != "" {
			receivers, err = parseReceivers(rcvrs, isBitcoin)
			if err != nil {
				return err
			}
		} else {
			receivers = []arksdk.Receiver{arksdk.NewLiquidReceiver(to, amount)}
		}
	} else {
		return fmt.Errorf("unsupported network: %s", net)
	}

	if len(receivers) == 0 {
		return fmt.Errorf("no receivers specified")
	}

	if isBitcoin {
		return sendCovenantLess(ctx, receivers)
	}
	return sendCovenant(receivers)
}

func balance(ctx *cli.Context) error {
	bal, err := arkSdkClient.Balance(
		context.Background(),
		ctx.Bool(expiryDetailsFlag.Name),
	)
	if err != nil {
		return err
	}
	return printJSON(bal)
}

func redeem(ctx *cli.Context) error {
	address, amount := ctx.String(addressFlag.Name), ctx.Uint64(amountToRedeemFlag.Name)
	force := ctx.Bool(forceFlag.Name)

	if force {
		err := arkSdkClient.UnilateralRedeem(context.Background())
		if err != nil {
			return err
		}
		return nil
	}

	txID, err := arkSdkClient.CollaborativeRedeem(
		context.Background(),
		address,
		amount,
		ctx.Bool(expiryDetailsFlag.Name),
	)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{
		"txid": txID,
	})
}

func getArkSdkClient(ctx *cli.Context) (arksdk.ArkClient, error) {
	cfgStore, err := getConfigStore(ctx.String(datadirFlag.Name))
	if err != nil {
		return nil, err
	}
	cfgData, err := cfgStore.GetData(context.Background())
	if err != nil {
		return nil, err
	}
	net := getNetwork(ctx, cfgData)

	if isBtcChain(net) {
		return loadOrCreateClient(
			arksdk.LoadCovenantlessClient,
			arksdk.NewCovenantlessClient,
			cfgStore,
		)
	}
	if isLiquidChain(net) {
		return loadOrCreateClient(
			arksdk.LoadCovenantClient,
			arksdk.NewCovenantClient,
			cfgStore,
		)
	}
	return nil, fmt.Errorf("unsupported network: %s", net)
}

func loadOrCreateClient(
	loadFunc,
	newFunc func(store.ConfigStore) (arksdk.ArkClient, error),
	store store.ConfigStore,
) (arksdk.ArkClient, error) {
	client, err := loadFunc(store)
	if errors.Is(err, arksdk.ErrNotInitialized) {
		client, err = newFunc(store)
	}
	return client, err
}

func getConfigStore(dataDir string) (store.ConfigStore, error) {
	return filestore.NewConfigStore(dataDir)
}

func getNetwork(ctx *cli.Context, configData *store.StoreData) string {
	if configData == nil {
		return strings.ToLower(ctx.String("network"))
	}
	return configData.Network.Name
}

func isBtcChain(network string) bool {
	return network == common.Bitcoin.Name ||
		network == common.BitcoinTestNet.Name ||
		network == common.BitcoinRegTest.Name
}

func isLiquidChain(network string) bool {
	return network == common.Liquid.Name ||
		network == common.LiquidTestNet.Name ||
		network == common.LiquidRegTest.Name
}

func parseReceivers(rcvrs string, isBitcoin bool) ([]arksdk.Receiver, error) {
	if isBitcoin {
		return arksdk.NewBitcoinReceiversFromJSON(rcvrs)
	}
	return arksdk.NewLiquidReceiversFromJSON(rcvrs)
}

func sendCovenantLess(ctx *cli.Context, receivers []arksdk.Receiver) error {
	txID, err := arkSdkClient.SendAsync(
		context.Background(),
		ctx.Bool(enableExpiryCoinselectFlag.Name),
		receivers,
	)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{"txid": txID})
}

func sendCovenant(receivers []arksdk.Receiver) error {
	var onchainReceivers, offchainReceivers []arksdk.Receiver

	for _, receiver := range receivers {
		if receiver.IsOnchain() {
			onchainReceivers = append(onchainReceivers, receiver)
		} else {
			offchainReceivers = append(offchainReceivers, receiver)
		}
	}

	if len(onchainReceivers) > 0 {
		txID, err := arkSdkClient.SendOnChain(context.Background(), onchainReceivers)
		if err != nil {
			return err
		}
		return printJSON(map[string]interface{}{"txid": txID})
	}

	if len(offchainReceivers) > 0 {
		txID, err := arkSdkClient.SendOffChain(context.Background(), false, offchainReceivers)
		if err != nil {
			return err
		}
		return printJSON(map[string]interface{}{"txid": txID})
	}

	return nil
}

func decrypt(encrypted, password []byte) ([]byte, error) {
	if len(encrypted) == 0 {
		return nil, fmt.Errorf("missing encrypted mnemonic")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("missing decryption password")
	}

	salt := encrypted[len(encrypted)-32:]
	data := encrypted[:len(encrypted)-32]
	key, _, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	// #nosec G407
	nonce, text := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, text, nil)
}

func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	key, err := scrypt.Key(password, salt, scryptKeyLength, 8, 1, 32)
	return key, salt, err
}

func readPassword(ctx *cli.Context) ([]byte, error) {
	password := []byte(ctx.String("password"))
	if len(password) == 0 {
		fmt.Print("unlock your wallet with password: ")
		var err error
		password, err = term.ReadPassword(syscall.Stdin)
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
