package main

import (
	"encoding/hex"
	"fmt"
	"syscall"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/term"
)

func readPassword() ([]byte, error) {
	fmt.Print("password: ")
	return term.ReadPassword(int(syscall.Stdin))
}

func privateKeyFromPassword() (*secp256k1.PrivateKey, error) {
	state, err := getState()
	if err != nil {
		return nil, err
	}

	encryptedPrivateKeyString, ok := state["encrypted_private_key"]
	if !ok {
		return nil, fmt.Errorf("encrypted private key not found")
	}

	encryptedPrivateKey, err := hex.DecodeString(encryptedPrivateKeyString)
	if err != nil {
		return nil, err
	}

	password, err := readPassword()
	if err != nil {
		return nil, err
	}

	cypher := NewAES128Cypher()
	privateKeyBytes, err := cypher.Decrypt(encryptedPrivateKey, password)
	if err != nil {
		return nil, err
	}

	privateKey := secp256k1.PrivKeyFromBytes(privateKeyBytes)
	return privateKey, nil
}
