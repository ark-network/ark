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
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
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
	fmt.Println("key unlocked")

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

func handleRoundStream(
	ctx *cli.Context,
	client arkv1.ArkServiceClient,
	paymentID string,
	vtxosToSign []vtxo,
	secKey *secp256k1.PrivateKey,
) (poolTxID string, err error) {
	stream, err := client.GetEventStream(ctx.Context, &arkv1.GetEventStreamRequest{})
	if err != nil {
		return "", err
	}

	var pingStop func()
	pingReq := &arkv1.PingRequest{
		PaymentId: paymentID,
	}
	for pingStop == nil {
		pingStop = ping(ctx, client, pingReq)
	}

	defer pingStop()

	for {
		event, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		if event.GetRoundFailed() != nil {
			pingStop()
			return "", fmt.Errorf("round failed: %s", event.GetRoundFailed().GetReason())
		}

		if event.GetRoundFinalization() != nil {
			// stop pinging as soon as we receive some forfeit txs
			pingStop()
			forfeits := event.GetRoundFinalization().GetForfeitTxs()
			signedForfeits := make([]string, 0)

			fmt.Println("signing forfeit txs...")

			explorer := NewExplorer()

			for _, forfeit := range forfeits {
				pset, err := psetv2.NewPsetFromBase64(forfeit)
				if err != nil {
					return "", err
				}

				for _, input := range pset.Inputs {
					inputTxid := chainhash.Hash(input.PreviousTxid).String()

					for _, coin := range vtxosToSign {
						// check if it contains one of the input to sign
						if inputTxid == coin.txid {
							if err := signPset(pset, explorer, secKey); err != nil {
								return "", err
							}

							signedPset, err := pset.ToBase64()
							if err != nil {
								return "", err
							}

							signedForfeits = append(signedForfeits, signedPset)
						}
					}
				}
			}

			// if no forfeit txs have been signed, start pinging again and wait for the next round
			if len(signedForfeits) == 0 {
				fmt.Println("no forfeit txs to sign, waiting for the next round...")
				pingStop = nil
				for pingStop == nil {
					pingStop = ping(ctx, client, pingReq)
				}
				continue
			}

			fmt.Printf("%d forfeit txs signed, finalizing payment...\n", len(signedForfeits))
			_, err = client.FinalizePayment(ctx.Context, &arkv1.FinalizePaymentRequest{
				SignedForfeitTxs: signedForfeits,
			})
			if err != nil {
				return "", err
			}

			continue
		}

		if event.GetRoundFinalized() != nil {
			return event.GetRoundFinalized().GetPoolTxid(), nil
		}
	}

	return "", fmt.Errorf("stream closed unexpectedly")
}

// send 1 ping message every 5 seconds to signal to the ark service that we are still alive
// returns a function that can be used to stop the pinging
func ping(ctx *cli.Context, client arkv1.ArkServiceClient, req *arkv1.PingRequest) func() {
	_, err := client.Ping(ctx.Context, req)
	if err != nil {
		return nil
	}

	ticker := time.NewTicker(5 * time.Second)

	go func(t *time.Ticker) {
		for range t.C {
			// nolint
			client.Ping(ctx.Context, req)
		}
	}(ticker)

	return ticker.Stop
}
