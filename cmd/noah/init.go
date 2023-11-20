package main

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
)

var (
	passwordFlag = cli.StringFlag{
		Name:     "password",
		Usage:    "password to encrypt private key",
		Value:    "",
		Required: true,
	}

	privateKeyFlag = cli.StringFlag{
		Name:     "prvkey",
		Usage:    "optional, private key to encrypt",
		Value:    "",
		Required: false,
	}
)

var initCommand = cli.Command{
	Name:   "init",
	Usage:  "Initialize Noah wallet private key, encrypted with password",
	Action: initAction,
	Flags: []cli.Flag{
		&passwordFlag,
		&privateKeyFlag,
	},
}

func initAction(ctx *cli.Context) error {
	privateKeyString := ctx.String("prvkey")
	password := ctx.String("password")

	if len(password) <= 0 {
		return cli.Exit("password cannot be empty", 1)
	}

	var privateKey *secp256k1.PrivateKey

	if len(privateKeyString) <= 0 {
		privKey, err := generateRandomPrivateKey()
		if err != nil {
			return err
		}
		privateKey = privKey
	} else {
		privKeyBytes, err := hex.DecodeString(privateKeyString)
		if err != nil {
			return err
		}

		privateKey = secp256k1.PrivKeyFromBytes(privKeyBytes)
	}

	cypher := NewAES128Cypher()

	encryptedPrivateKey, err := cypher.Encrypt(privateKey.Serialize(), []byte(password))
	if err != nil {
		return err
	}

	passwordHash := hashPassword([]byte(password))

	state := map[string]string{
		"encrypted_private_key": hex.EncodeToString(encryptedPrivateKey),
		"password_hash":         hex.EncodeToString(passwordHash),
	}

	if err := setState(state); err != nil {
		return err
	}

	return nil
}

func generateRandomPrivateKey() (*secp256k1.PrivateKey, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return privKey, nil
}
