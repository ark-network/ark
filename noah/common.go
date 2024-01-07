package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"syscall"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
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

func getWalletPublicKey() (*secp256k1.PublicKey, error) {
	state, err := getState()
	if err != nil {
		return nil, err
	}

	publicKeyString, ok := state["public_key"]
	if !ok {
		return nil, fmt.Errorf("public key not found")
	}

	_, publicKey, err := common.DecodePubKey(publicKeyString)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func getServiceProviderPublicKey() (*secp256k1.PublicKey, error) {
	state, err := getState()
	if err != nil {
		return nil, err
	}

	arkPubKey, ok := state["ark_pubkey"]
	if !ok {
		return nil, fmt.Errorf("ark public key not found")
	}

	_, pubKey, err := common.DecodePubKey(arkPubKey)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
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

func getOffchainBalance(
	ctx *cli.Context, client arkv1.ArkServiceClient, addr string,
) (uint64, error) {
	vtxos, err := getVtxos(ctx, client, addr)
	if err != nil {
		return 0, err
	}
	var balance uint64
	for _, vtxo := range vtxos {
		balance += vtxo.amount
	}
	return balance, nil
}

type utxo struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Amount uint64 `json:"value"`
	Asset  string `json:"asset"`
}

func coinSelectOnchain(addr string, amount uint64) ([]utxo, uint64, error) {
	utxos, err := getOnchainUtxos(addr)
	if err != nil {
		return nil, 0, err
	}

	selected := make([]utxo, 0)
	selectedAmount := uint64(0)

	for _, utxo := range utxos {
		if selectedAmount >= amount {
			break
		}

		selected = append(selected, utxo)
		selectedAmount += utxo.Amount
	}

	if selectedAmount < amount {
		return nil, 0, fmt.Errorf("insufficient balance: %d to cover %d", selectedAmount, amount)
	}

	change := selectedAmount - amount

	return selected, change, nil
}

func getOnchainUtxos(addr string) ([]utxo, error) {
	_, net, err := getNetwork()
	if err != nil {
		return nil, err
	}

	baseUrl := explorerUrl[net.Name]
	resp, err := http.Get(fmt.Sprintf("%s/address/%s/utxo", baseUrl, addr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(string(body))
	}
	payload := []utxo{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func getOnchainBalance(addr string) (uint64, error) {
	payload, err := getOnchainUtxos(addr)
	if err != nil {
		return 0, err
	}

	_, net, err := getNetwork()
	if err != nil {
		return 0, err
	}

	balance := uint64(0)
	for _, p := range payload {
		if p.Asset != net.AssetID {
			continue
		}
		balance += p.Amount
	}
	return balance, nil
}

func getTxHex(txid string) (string, error) {
	_, net, err := getNetwork()
	if err != nil {
		return "", err
	}

	baseUrl := explorerUrl[net.Name]
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s/hex", baseUrl, txid))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf(string(body))
	}

	return string(body), nil
}

func broadcast(txHex string) (string, error) {
	_, net, err := getNetwork()
	if err != nil {
		return "", err
	}

	body := bytes.NewBuffer([]byte(txHex))

	baseUrl := explorerUrl[net.Name]
	resp, err := http.Post(fmt.Sprintf("%s/tx", baseUrl), "text/plain", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bodyResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf(string(bodyResponse))
	}

	return string(bodyResponse), nil
}

func getNetwork() (*common.Network, *network.Network, error) {
	state, err := getState()
	if err != nil {
		return nil, nil, err
	}

	net, ok := state["network"]
	if !ok {
		return &common.MainNet, &network.Liquid, nil
	}
	if net == "testnet" {
		return &common.TestNet, &network.Testnet, nil
	}
	return &common.MainNet, &network.Liquid, nil
}

func getAddress() (offchainAddr, onchainAddr string, err error) {
	publicKey, err := getWalletPublicKey()
	if err != nil {
		return
	}

	aspPublicKey, err := getServiceProviderPublicKey()
	if err != nil {
		return
	}

	arkNet, liquidNet, err := getNetwork()
	if err != nil {
		return
	}

	arkAddr, err := common.EncodeAddress(arkNet.Addr, publicKey, aspPublicKey)
	if err != nil {
		return
	}

	p2wpkh := payment.FromPublicKey(publicKey, liquidNet, nil)
	liquidAddr, err := p2wpkh.WitnessPubKeyHash()
	if err != nil {
		return
	}

	offchainAddr = arkAddr
	onchainAddr = liquidAddr

	return
}

func printJSON(resp interface{}) error {
	jsonBytes, err := json.MarshalIndent(resp, "", "\t")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonBytes))
	return nil
}
