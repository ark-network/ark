package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"syscall"

	"github.com/ark-network/ark/common"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/term"
)

func hashPassword(password []byte) []byte {
	hash := sha256.Sum256(password)
	return hash[:]
}

func verifyPassword(password []byte) error {
	state, err := getState()
	if err != nil {
		return err
	}

	passwordHashString, ok := state["password_hash"]
	if !ok {
		return fmt.Errorf("password hash not found")
	}

	passwordHash, err := hex.DecodeString(passwordHashString)
	if err != nil {
		return err
	}

	currentPassHash := hashPassword(password)

	if !bytes.Equal(passwordHash, currentPassHash) {
		return fmt.Errorf("invalid password")
	}

	return nil
}

func readPassword() ([]byte, error) {
	fmt.Print("password: ")
	passwordInput, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // new line
	if err != nil {
		return nil, err
	}

	err = verifyPassword(passwordInput)
	if err != nil {
		return nil, err
	}

	return passwordInput, nil
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

func getServiceProviderPublicKey() (*secp256k1.PublicKey, error) {
	state, err := getState()
	if err != nil {
		return nil, err
	}

	arkURL, ok := state["ark_url"]
	if !ok {
		return nil, fmt.Errorf("ark url not found")
	}

	arkPubKey, _, err := common.DecodeUrl(arkURL)
	if err != nil {
		return nil, err
	}

	_, publicKey, err := common.DecodePubKey(arkPubKey)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}
