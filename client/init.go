package main

import (
	"encoding/hex"
	"fmt"
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
	Usage:  "initialize the wallet with an encryption password, and connect it to an ASP",
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

	if err := connectToAsp(ctx, net, url); err != nil {
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

func connectToAsp(ctx *cli.Context, net, url string) error {
	client, close, err := getClient(ctx, url)
	if err != nil {
		return err
	}
	defer close()

	resp, err := client.GetInfo(ctx.Context, &arkv1.GetInfoRequest{})
	if err != nil {
		return err
	}

	return setState(map[string]interface{}{
		"ark_url":      url,
		"network":      net,
		"ark_pubkey":   resp.Pubkey,
		"ark_lifetime": resp.Lifetime,
		"exit_delay":   resp.ExitDelay,
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

	encryptedPrivateKey, err := NewAES128Cypher().Encrypt(privateKey.Serialize(), []byte(password))
	if err != nil {
		return err
	}

	passwordHash := hashPassword([]byte(password))

	state := map[string]interface{}{
		"encrypted_private_key": hex.EncodeToString(encryptedPrivateKey),
		"password_hash":         hex.EncodeToString(passwordHash),
		"public_key":            hex.EncodeToString(privateKey.PubKey().SerializeCompressed()),
	}

	if err := setState(state); err != nil {
		return err
	}

	fmt.Println("wallet initialized")
	return nil
}
