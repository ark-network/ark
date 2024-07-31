package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"syscall"

	arksdk "github.com/ark-network/ark-sdk"
	"github.com/ark-network/ark-sdk/store"
	filestore "github.com/ark-network/ark-sdk/store/file"
	"github.com/ark-network/ark/common"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

const (
	DatadirEnvVar = "ARK_WALLET_DATADIR"
)

var (
	version = "alpha"

	cntx         = context.Background()
	arkSdkClient arksdk.ArkClient
)

var (
	initCommand = cli.Command{
		Name:  "init",
		Usage: "Initialize your Ark wallet with an encryption password, and connect it to an ASP",
		Action: func(ctx *cli.Context) error {
			return initArkSdk(ctx)
		},
		Flags: []cli.Flag{&passwordFlag, &privateKeyFlag, &networkFlag, &urlFlag, &explorerFlag},
	}

	receiveCommand = cli.Command{
		Name:  "receive",
		Usage: "Shows both onchain and offchain addresses",
		Action: func(ctx *cli.Context) error {
			return receive(ctx)
		},
	}

	onboardCommand = cli.Command{
		Name:  "onboard",
		Usage: "Onboard the Ark by lifting your funds",
		Action: func(ctx *cli.Context) error {
			return onboard(ctx)
		},
		Flags: []cli.Flag{&amountOnboardFlag, &trustedOnboardFlag, &passwordFlag},
	}

	balanceCommand = cli.Command{
		Name:  "balance",
		Usage: "Shows the onchain and offchain balance of the Ark wallet",
		Action: func(ctx *cli.Context) error {
			return balance(ctx)
		},
		Flags: []cli.Flag{&expiryDetailsFlag},
	}

	sendCommand = cli.Command{
		Name:  "send",
		Usage: "Send your onchain or offchain funds to one or many receivers",
		Action: func(ctx *cli.Context) error {
			return send(ctx)
		},
		Flags: []cli.Flag{&receiversFlag, &toFlag, &amountFlag, &passwordFlag, &enableExpiryCoinselectFlag},
	}

	redeemCommand = cli.Command{
		Name:  "redeem",
		Usage: "Redeem your offchain funds, either collaboratively or unilaterally",
		Flags: []cli.Flag{&addressFlag, &amountToRedeemFlag, &forceFlag, &passwordFlag, &enableExpiryCoinselectFlag},
		Action: func(ctx *cli.Context) error {
			return redeem(ctx)
		},
	}

	configCommand = cli.Command{
		Name:  "config",
		Usage: "Shows configuration of the Ark wallet",
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
		Flags: []cli.Flag{&passwordFlag},
	}
)

var (
	datadirFlag = &cli.StringFlag{
		Name:     "datadir",
		Usage:    "Specify the data directory",
		Required: false,
		Value:    common.AppDataDir("ark-cli", false),
		EnvVars:  []string{DatadirEnvVar},
	}
	passwordFlag = cli.StringFlag{
		Name:     "password",
		Usage:    "password to unlock the wallet",
		Required: false,
		Hidden:   true,
	}
	amountOnboardFlag = cli.Uint64Flag{
		Name:  "amount",
		Usage: "amount to onboard in sats",
	}
	trustedOnboardFlag = cli.BoolFlag{
		Name:  "trusted",
		Usage: "trusted onboard",
	}
	expiryDetailsFlag = cli.BoolFlag{
		Name:     "compute-expiry-details",
		Usage:    "compute client-side the VTXOs expiry time",
		Value:    false,
		Required: false,
	}
	privateKeyFlag = cli.StringFlag{
		Name:  "prvkey",
		Usage: "optional, private key to encrypt",
	}
	networkFlag = cli.StringFlag{
		Name:  "network",
		Usage: "network to use (for liquid: liquid, liquidtestnet, liquidregtest and for bitcoin; bitcoin, testnet,regtest)",
		Value: "liquid",
	}
	urlFlag = cli.StringFlag{
		Name:     "ark-url",
		Usage:    "the url of the ASP to connect to",
		Required: true,
	}
	explorerFlag = cli.StringFlag{
		Name:  "explorer",
		Usage: "the url of the explorer to use",
	}
	receiversFlag = cli.StringFlag{
		Name:  "receivers",
		Usage: "receivers of the send transaction, JSON encoded: '[{\"to\": \"<...>\", \"amount\": <...>}, ...]'",
	}
	toFlag = cli.StringFlag{
		Name:  "to",
		Usage: "address of the recipient",
	}
	amountFlag = cli.Uint64Flag{
		Name:  "amount",
		Usage: "amount to send in sats",
	}
	enableExpiryCoinselectFlag = cli.BoolFlag{
		Name:  "enable-expiry-coinselect",
		Usage: "select vtxos that are about to expire first",
		Value: false,
	}
	addressFlag = cli.StringFlag{
		Name:     "address",
		Usage:    "main chain address receiving the redeeemed VTXO",
		Value:    "",
		Required: false,
	}
	amountToRedeemFlag = cli.Uint64Flag{
		Name:     "amount",
		Usage:    "amount to redeem",
		Value:    0,
		Required: false,
	}
	forceFlag = cli.BoolFlag{
		Name:     "force",
		Usage:    "force redemption without collaborate with the Ark service provider",
		Value:    false,
		Required: false,
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
		&onboardCommand,
	)
	app.Flags = []cli.Flag{
		datadirFlag,
	}

	app.Before = func(ctx *cli.Context) error {
		sdk, err := getArkSdkClient(ctx)
		if err != nil {
			return fmt.Errorf("error while initializing ark sdk client: %v", err)
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

func getArkSdkClient(ctx *cli.Context) (arksdk.ArkClient, error) {
	dataDir := ctx.String("datadir")
	configStore, err := filestore.NewConfigStore(dataDir)
	if err != nil {
		return nil, err
	}

	configData, err := configStore.GetData(context.Background())
	if err != nil {
		return nil, err
	}

	net := getNetwork(ctx, configData)
	switch net {
	//TODO once arksdk is updated to support covenantless, create arksdk client base on network
	case common.Liquid.Name, common.LiquidTestNet.Name, common.LiquidRegTest.Name:
		if !isArkSdkClientInitialized(configData) {
			sdk, err := arksdk.New(configStore)
			if err != nil {
				return nil, err
			}

			arkSdkClient = sdk
		} else {
			sdk, err := arksdk.Load(configStore)
			if err != nil {
				return nil, err
			}

			arkSdkClient = sdk
		}
	case common.Bitcoin.Name, common.BitcoinTestNet.Name, common.BitcoinRegTest.Name:
		//TODO
		if !isArkSdkClientInitialized(configData) {

		} else {

		}
	}

	return arkSdkClient, nil
}

func isArkSdkClientInitialized(configData *store.StoreData) bool {
	return configData != nil
}

func getNetwork(ctx *cli.Context, configData *store.StoreData) string {
	if configData == nil {
		return strings.ToLower(ctx.String("network"))
	}

	return configData.Network.Name

}

func initArkSdk(ctx *cli.Context) error {
	key := ctx.String("prvkey")
	url := ctx.String("ark-url")

	password, err := readPassword(ctx)
	if err != nil {
		return err
	}

	return arkSdkClient.Init(
		cntx,
		arksdk.InitArgs{
			ClientType: arksdk.GrpcClient,
			WalletType: arksdk.SingleKeyWallet,
			AspUrl:     url,
			Seed:       key,
			Password:   string(password),
		},
	)
}

func balance(ctx *cli.Context) error {
	computeExpiryDetails := ctx.Bool(expiryDetailsFlag.Name)
	bal, err := arkSdkClient.Balance(cntx, computeExpiryDetails)
	if err != nil {
		return err
	}

	return printJSON(bal)
}

func config(ctx *cli.Context) error {
	cfg, err := arkSdkClient.GetConfigData(cntx)
	if err != nil {
		return err
	}

	return printJSON(cfg)
}

func onboard(ctx *cli.Context) error {
	amount := ctx.Uint64(amountOnboardFlag.Name)

	txID, err := arkSdkClient.Onboard(cntx, amount)
	if err != nil {
		return err
	}

	fmt.Println("onboard_txid:", txID)

	return nil
}

func send(ctx *cli.Context) error {
	if !ctx.IsSet("receivers") && !ctx.IsSet("to") && !ctx.IsSet("amount") {
		return fmt.Errorf("missing destination, either use --to and --amount to send or --receivers to send to many")
	}
	receivers := ctx.String("receivers")
	to := ctx.String("to")
	amount := ctx.Uint64("amount")

	var receiversJSON []arksdk.Receiver
	if len(receivers) > 0 {
		if err := json.Unmarshal([]byte(receivers), &receiversJSON); err != nil {
			return fmt.Errorf("invalid receivers: %s", err)
		}
	} else {
		receiversJSON = []arksdk.Receiver{
			{
				To:     to,
				Amount: amount,
			},
		}
	}

	if len(receiversJSON) <= 0 {
		return fmt.Errorf("no receivers specified")
	}

	onchainReceivers := make([]arksdk.Receiver, 0)
	offchainReceivers := make([]arksdk.Receiver, 0)

	for _, receiver := range receiversJSON {
		if receiver.IsOnChain() {
			onchainReceivers = append(onchainReceivers, receiver)
		} else {
			offchainReceivers = append(offchainReceivers, receiver)
		}
	}

	if len(onchainReceivers) > 0 {
		txID, err := arkSdkClient.SendOnChain(cntx, onchainReceivers)
		if err != nil {
			return err
		}

		return printJSON(map[string]interface{}{
			"txid": txID,
		})
	}

	if len(offchainReceivers) > 0 {
		txID, err := arkSdkClient.SendOffChain(
			cntx, false, offchainReceivers,
		)
		if err != nil {
			return err
		}

		return printJSON(map[string]interface{}{
			"txid": txID,
		})
	}

	return nil
}

func receive(ctx *cli.Context) error {
	offchainAddr, onchainAddr, err := arkSdkClient.Receive(cntx)
	if err != nil {
		return err
	}

	return printJSON(map[string]interface{}{
		"offchain_address": offchainAddr,
		"onchain_address":  onchainAddr,
	})
}

func redeem(ctx *cli.Context) error {
	address := ctx.String("address")
	amount := ctx.Uint64("amount")
	computeExpiryDetails := ctx.Bool(expiryDetailsFlag.Name)

	txID, err := arkSdkClient.CollaborativeRedeem(
		cntx, address, amount, computeExpiryDetails,
	)
	if err != nil {
		return err
	}

	return printJSON(map[string]interface{}{
		"txid": txID,
	})
}

func dumpPrivKey(ctx *cli.Context) error {
	password, err := readPassword(ctx)
	if err != nil {
		return err
	}

	walletStore, err := arkSdkClient.GetWalletStore(cntx, string(password))
	if err != nil {
		return err
	}

	walletData, err := walletStore.GetWallet()
	if err != nil {
		return err
	}

	encryptedPrivateKey := walletData.EncryptedPrvkey
	privateKeyBytes, err := decrypt(encryptedPrivateKey, password)
	if err != nil {
		return err
	}

	privateKey := secp256k1.PrivKeyFromBytes(privateKeyBytes)

	return printJSON(map[string]interface{}{
		"private_key": hex.EncodeToString(privateKey.Serialize()),
	})
}

func decrypt(encrypted, password []byte) ([]byte, error) {
	defer debug.FreeOSMemory()

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
	nonce, text := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, text, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}
	return plaintext, nil
}

// deriveKey derives a 32 byte array key from a custom passhprase
func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	// 2^20 = 1048576 recommended length for key-stretching
	// check the doc for other recommended values:
	// https://godoc.org/golang.org/x/crypto/scrypt
	key, err := scrypt.Key(password, salt, 1048576, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

func readPassword(ctx *cli.Context) ([]byte, error) {
	password := []byte(ctx.String("password"))

	if len(password) == 0 {
		fmt.Print("unlock your wallet with password: ")
		var err error
		password, err = term.ReadPassword(syscall.Stdin)
		fmt.Println() // new line
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
