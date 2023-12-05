package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func coinSelect(vtxos []vtxo, amount uint64) ([]vtxo, uint64, error) {
	selected := make([]vtxo, 0)
	selectedAmount := uint64(0)

	for _, vtxo := range vtxos {
		if selectedAmount >= amount {
			break
		}

		selected = append(selected, vtxo)
		selectedAmount += vtxo.amount
	}

	if selectedAmount < amount {
		return nil, 0, fmt.Errorf("insufficient balance: %d to cover %d", selectedAmount, amount)
	}

	change := selectedAmount - amount

	return selected, change, nil
}

func computeBalance(vtxos []vtxo) uint64 {
	var balance uint64
	for _, vtxo := range vtxos {
		balance += vtxo.amount
	}
	return balance
}

func getAddress() (string, error) {
	privateKey, err := privateKeyFromPassword()
	if err != nil {
		return "", err
	}

	publicKey := privateKey.PubKey()

	aspPublicKey, err := getServiceProviderPublicKey()
	if err != nil {
		return "", err
	}

	addr, err := common.EncodeAddress(common.MainNet.Addr, publicKey, aspPublicKey)
	if err != nil {
		return "", err
	}

	return addr, nil
}

func printJSON(resp interface{}) error {
	jsonBytes, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	fmt.Println(string(jsonBytes))
	return nil
}
