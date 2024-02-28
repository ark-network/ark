package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
)

var (
	passwordFlag = cli.StringFlag{
		Name:     "password",
		Usage:    "password to encrypt private key",
		Required: true,
	}

	privateKeyFlag = cli.StringFlag{
		Name:  "prvkey",
		Usage: "optional, private key to encrypt",
	}
	networkFlag = cli.StringFlag{
		Name:  "network",
		Usage: "network to use (mainnet, testnet)",
		Value: "testnet",
	}
	urlFlag = cli.StringFlag{
		Name:     "ark-url",
		Usage:    "the url of the ASP to connect to",
		Required: true,
	}
)

var initCommand = cli.Command{
	Name:   "init",
	Usage:  "Initialize your Ark wallet with an encryption password, and connect it to an ASP",
	Action: initAction,
	Flags:  []cli.Flag{&passwordFlag, &privateKeyFlag, &networkFlag, &urlFlag},
}

func initAction(ctx *cli.Context) error {
	key := ctx.String("prvkey")
	password := ctx.String("password")
	net := strings.ToLower(ctx.String("network"))
	url := ctx.String("ark-url")

	if len(password) <= 0 {
		return fmt.Errorf("invalid password")
	}
	if len(url) <= 0 {
		return fmt.Errorf("invalid ark url")
	}
	if net != "mainnet" && net != "testnet" {
		return fmt.Errorf("invalid network")
	}

	if err := connectToAsp(ctx.Context, net, url); err != nil {
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

func connectToAsp(ctx context.Context, net, url string) error {
	client, close, err := getClient(url)
	if err != nil {
		return err
	}
	defer close()

	resp, err := client.GetInfo(ctx, &arkv1.GetInfoRequest{})
	if err != nil {
		return err
	}

	return setState(map[string]string{
		ASP_URL:               url,
		NETWORK:               net,
		ASP_PUBKEY:            resp.Pubkey,
		ROUND_LIFETIME:        strconv.Itoa(int(resp.GetRoundLifetime())),
		UNILATERAL_EXIT_DELAY: strconv.Itoa(int(resp.GetUnilateralExitDelay())),
	})
}

func initWallet(ctx *cli.Context, key, password string) error {
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
	encryptedPrivateKey, err := cypher.encrypt(buf, []byte(password))
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

	if err := setState(state); err != nil {
		return err
	}

	fmt.Println("wallet initialized")
	return nil
}
