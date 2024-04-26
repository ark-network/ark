package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/network"
)

var (
	privateKeyFlag = cli.StringFlag{
		Name:  "prvkey",
		Usage: "optional, private key to encrypt",
	}
	networkFlag = cli.StringFlag{
		Name:  "network",
		Usage: "network to use (liquid, testnet, regtest)",
		Value: "testnet",
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
)

var initCommand = cli.Command{
	Name:   "init",
	Usage:  "Initialize your Ark wallet with an encryption password, and connect it to an ASP",
	Action: initAction,
	Flags:  []cli.Flag{&passwordFlag, &privateKeyFlag, &networkFlag, &urlFlag, &explorerFlag},
}

func initAction(ctx *cli.Context) error {
	key := ctx.String("prvkey")
	net := strings.ToLower(ctx.String("network"))
	url := ctx.String("ark-url")
	explorer := ctx.String("explorer")

	var explorerURL string

	if len(url) <= 0 {
		return fmt.Errorf("invalid ark url")
	}
	if net != "liquid" && net != "testnet" && net != "regtest" {
		return fmt.Errorf("invalid network")
	}

	if len(explorer) > 0 {
		explorerURL = explorer
		_, network := networkFromString(net)
		if err := testEsploraEndpoint(network, explorerURL); err != nil {
			return fmt.Errorf("failed to connect with explorer: %s", err)
		}
	} else {
		explorerURL = explorerUrl[net]
	}

	if err := connectToAsp(ctx, net, url, explorerURL); err != nil {
		return err
	}

	password, err := readPassword(ctx, false)
	if err != nil {
		return err
	}

	return initWallet(ctx, key, password)
}

func generateRandomPrivateKey() (*secp256k1.PrivateKey, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func connectToAsp(ctx *cli.Context, net, url, explorer string) error {
	client, close, err := getClient(url)
	if err != nil {
		return err
	}
	defer close()

	resp, err := client.GetInfo(ctx.Context, &arkv1.GetInfoRequest{})
	if err != nil {
		return err
	}

	return setState(ctx, map[string]string{
		ASP_URL:               url,
		NETWORK:               net,
		ASP_PUBKEY:            resp.Pubkey,
		ROUND_LIFETIME:        strconv.Itoa(int(resp.GetRoundLifetime())),
		UNILATERAL_EXIT_DELAY: strconv.Itoa(int(resp.GetUnilateralExitDelay())),
		EXPLORER:              explorer,
	})
}

func initWallet(ctx *cli.Context, key string, password []byte) error {
	var privateKey *secp256k1.PrivateKey
	if len(key) <= 0 {
		privKey, err := generateRandomPrivateKey()
		if err != nil {
			return err
		}
		privateKey = privKey
	} else {
		privKeyBytes, err := hex.DecodeString(key)
		if err != nil {
			return err
		}

		privateKey = secp256k1.PrivKeyFromBytes(privKeyBytes)
	}

	cypher := newAES128Cypher()
	buf := privateKey.Serialize()
	encryptedPrivateKey, err := cypher.encrypt(buf, password)
	if err != nil {
		return err
	}

	passwordHash := hashPassword([]byte(password))

	pubkey := privateKey.PubKey().SerializeCompressed()
	state := map[string]string{
		ENCRYPTED_PRVKEY: hex.EncodeToString(encryptedPrivateKey),
		PASSWORD_HASH:    hex.EncodeToString(passwordHash),
		PUBKEY:           hex.EncodeToString(pubkey),
	}

	if err := setState(ctx, state); err != nil {
		return err
	}

	fmt.Println("wallet initialized")
	return nil
}

func testEsploraEndpoint(net *network.Network, url string) error {
	resp, err := http.Get(fmt.Sprintf("%s/asset/%s", url, net.AssetID))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(string(body))
	}

	return nil
}
