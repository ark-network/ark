package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"syscall"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
	"golang.org/x/term"
)

const (
	DUST = 450
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
	fmt.Print("unlock your wallet with password: ")
	passwordInput, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // new line
	if err != nil {
		return nil, err
	}

	if err := verifyPassword(passwordInput); err != nil {
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
		return nil, fmt.Errorf("invalid encrypted private key: %s", err)
	}

	password, err := readPassword()
	if err != nil {
		return nil, err
	}
	fmt.Println("wallet unlocked")

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

// vtxoList implements sort.Interface
type vtxoList []vtxo

func (ls vtxoList) Len() int {
	return len(ls)
}

// older vtxos first
func (ls vtxoList) Less(i, j int) bool {
	if ls[i].expireAt == nil || ls[j].expireAt == nil {
		return false
	}

	return ls[i].expireAt.Before(*ls[j].expireAt)
}

func (ls vtxoList) Swap(i, j int) {
	ls[i], ls[j] = ls[j], ls[i]
}

func coinSelect(vtxos []vtxo, amount uint64) ([]vtxo, uint64, error) {
	selected := make([]vtxo, 0)
	notSelected := make([]vtxo, 0)
	selectedAmount := uint64(0)

	// sort vtxos by expiration (older first)
	sort.Sort(vtxoList(vtxos))

	for _, vtxo := range vtxos {
		if selectedAmount >= amount {
			notSelected = append(notSelected, vtxo)
			break
		}

		selected = append(selected, vtxo)
		selectedAmount += vtxo.amount
	}

	if selectedAmount < amount {
		return nil, 0, fmt.Errorf("insufficient balance: %d to cover %d", selectedAmount, amount)
	}

	change := selectedAmount - amount

	if change < DUST {
		if len(notSelected) > 0 {
			selected = append(selected, notSelected[0])
			change += notSelected[0].amount
		}
	}

	return selected, change, nil
}

func getOffchainBalance(
	ctx *cli.Context, explorer Explorer, client arkv1.ArkServiceClient, addr string, withExpiration bool,
) (uint64, map[int64]uint64, error) {
	amountByExpiration := make(map[int64]uint64, 0)

	vtxos, err := getVtxos(ctx, explorer, client, addr, withExpiration)
	if err != nil {
		return 0, nil, err
	}
	var balance uint64
	for _, vtxo := range vtxos {
		balance += vtxo.amount

		if withExpiration {
			expiration := vtxo.expireAt.Unix()

			if _, ok := amountByExpiration[expiration]; !ok {
				amountByExpiration[expiration] = 0
			}

			amountByExpiration[expiration] += vtxo.amount
		}
	}

	return balance, amountByExpiration, nil
}

type utxo struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Amount uint64 `json:"value"`
	Asset  string `json:"asset"`
}

func getOnchainUtxos(addr string) ([]utxo, error) {
	_, net := getNetwork()
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

	_, net := getNetwork()
	balance := uint64(0)
	for _, p := range payload {
		if p.Asset != net.AssetID {
			continue
		}
		balance += p.Amount
	}
	return balance, nil
}

func getTxBlocktime(txid string) (confirmed bool, blocktime int64, err error) {
	_, net := getNetwork()
	baseUrl := explorerUrl[net.Name]
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s", baseUrl, txid))
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf(string(body))
	}

	var tx struct {
		Status struct {
			Confirmed bool  `json:"confirmed"`
			Blocktime int64 `json:"block_time"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &tx); err != nil {
		return false, 0, err
	}

	if !tx.Status.Confirmed {
		return false, -1, nil
	}

	return true, tx.Status.Blocktime, nil

}

func broadcast(txHex string) (string, error) {
	_, net := getNetwork()
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

func getNetwork() (*common.Network, *network.Network) {
	state, err := getState()
	if err != nil {
		return &common.TestNet, &network.Testnet
	}

	net, ok := state["network"]
	if !ok {
		return &common.MainNet, &network.Liquid
	}
	if net == "testnet" {
		return &common.TestNet, &network.Testnet
	}
	return &common.MainNet, &network.Liquid
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

	arkNet, liquidNet := getNetwork()

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
	receivers []*arkv1.Output,
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
			fmt.Println("round finalization started")

			poolPartialTx := event.GetRoundFinalization().GetPoolPartialTx()
			poolTransaction, err := psetv2.NewPsetFromBase64(poolPartialTx)
			if err != nil {
				return "", err
			}

			congestionTree, err := toCongestionTree(event.GetRoundFinalization().GetCongestionTree())
			if err != nil {
				return "", err
			}

			aspPublicKey, err := getServiceProviderPublicKey()
			if err != nil {
				return "", err
			}

			_, seconds, err := findSweepClosure(congestionTree)
			if err != nil {
				return "", err
			}

			// validate the congestion tree
			if err := tree.ValidateCongestionTree(
				congestionTree,
				poolPartialTx,
				aspPublicKey,
				int64(seconds),
			); err != nil {
				return "", err
			}

			// validate the receivers
			sweepLeaf, err := tree.SweepScript(aspPublicKey, seconds)
			if err != nil {
				return "", err
			}

			for _, receiver := range receivers {
				isOnChain, onchainScript, userPubKey, err := decodeReceiverAddress(receiver.Address)
				if err != nil {
					return "", err
				}

				if isOnChain {
					// collaborative exit case
					// search for the output in the pool tx
					found := false
					for _, output := range poolTransaction.Outputs {
						if bytes.Equal(output.Script, onchainScript) {
							if output.Value != receiver.Amount {
								return "", fmt.Errorf("invalid collaborative exit output amount: got %d, want %d", output.Value, receiver.Amount)
							}

							found = true
							break
						}
					}

					if !found {
						return "", fmt.Errorf("collaborative exit output not found: %s", receiver.Address)
					}

					continue
				}

				// off-chain send case
				// search for the output in congestion tree
				found := false

				// compute the receiver output taproot key
				vtxoScript, err := tree.VtxoScript(userPubKey)
				if err != nil {
					return "", err
				}

				vtxoTaprootTree := taproot.AssembleTaprootScriptTree(*vtxoScript, *sweepLeaf)
				root := vtxoTaprootTree.RootNode.TapHash()
				unspendableKey := tree.UnspendableKey()
				vtxoTaprootKey := schnorr.SerializePubKey(taproot.ComputeTaprootOutputKey(unspendableKey, root[:]))

				leaves := congestionTree.Leaves()
				for _, leaf := range leaves {
					tx, err := psetv2.NewPsetFromBase64(leaf.Tx)
					if err != nil {
						return "", err
					}

					for _, output := range tx.Outputs {
						if len(output.Script) == 0 {
							continue
						}
						if bytes.Equal(output.Script[2:], vtxoTaprootKey) {
							if output.Value != receiver.Amount {
								continue
							}

							found = true
							break
						}
					}

					if found {
						break
					}
				}

				if !found {
					return "", fmt.Errorf("off-chain send output not found: %s", receiver.Address)
				}
			}

			fmt.Println("congestion tree validated")

			forfeits := event.GetRoundFinalization().GetForfeitTxs()
			signedForfeits := make([]string, 0)

			fmt.Print("signing forfeit txs... ")

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
				fmt.Printf("\nno forfeit txs to sign, waiting for the next round...\n")
				pingStop = nil
				for pingStop == nil {
					pingStop = ping(ctx, client, pingReq)
				}
				continue
			}

			fmt.Printf("%d signed\n", len(signedForfeits))
			fmt.Print("finalizing payment... ")
			_, err = client.FinalizePayment(ctx.Context, &arkv1.FinalizePaymentRequest{
				SignedForfeitTxs: signedForfeits,
			})
			if err != nil {
				return "", err
			}
			fmt.Print("done.\n")
			fmt.Println("waiting for round finalization...")

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

func toCongestionTree(treeFromProto *arkv1.Tree) (tree.CongestionTree, error) {
	levels := make(tree.CongestionTree, 0, len(treeFromProto.Levels))

	for _, level := range treeFromProto.Levels {
		nodes := make([]tree.Node, 0, len(level.Nodes))

		for _, node := range level.Nodes {
			nodes = append(nodes, tree.Node{
				Txid:       node.Txid,
				Tx:         node.Tx,
				ParentTxid: node.ParentTxid,
				Leaf:       false,
			})
		}

		levels = append(levels, nodes)
	}

	for j, treeLvl := range levels {
		for i, node := range treeLvl {
			if len(levels.Children(node.Txid)) == 0 {
				levels[j][i].Leaf = true
			}
		}
	}

	return levels, nil
}

func decodeReceiverAddress(addr string) (
	isOnChainAddress bool,
	onchainScript []byte,
	userPubKey *secp256k1.PublicKey,
	err error,
) {
	outputScript, err := address.ToOutputScript(addr)
	if err != nil {
		_, userPubKey, _, err = common.DecodeAddress(addr)
		if err != nil {
			return
		}
		return false, nil, userPubKey, nil
	}

	return true, outputScript, nil, nil
}

func findSweepClosure(
	congestionTree tree.CongestionTree,
) (sweepClosure *taproot.TapElementsLeaf, seconds uint, err error) {
	root, err := congestionTree.Root()
	if err != nil {
		return
	}

	// find the sweep closure
	tx, err := psetv2.NewPsetFromBase64(root.Tx)
	if err != nil {
		return
	}

	for _, tapLeaf := range tx.Inputs[0].TapLeafScript {
		isSweep, _, lifetime, err := tree.DecodeSweepScript(tapLeaf.Script)
		if err != nil {
			continue
		}

		if isSweep {
			seconds = lifetime
			sweepClosure = &tapLeaf.TapElementsLeaf
			break
		}
	}

	if sweepClosure == nil {
		return nil, 0, fmt.Errorf("sweep closure not found")
	}

	return
}

func getRedeemBranches(
	ctx *cli.Context,
	explorer Explorer,
	client arkv1.ArkServiceClient,
	vtxos []vtxo,
) (map[string]RedeemBranch, error) {
	congestionTrees := make(map[string]tree.CongestionTree, 0) // poolTxid -> congestionTree
	redeemBranches := make(map[string]RedeemBranch, 0)         // vtxo.txid -> redeemBranch

	for _, vtxo := range vtxos {
		if _, ok := congestionTrees[vtxo.poolTxid]; !ok {
			round, err := client.GetRound(ctx.Context, &arkv1.GetRoundRequest{
				Txid: vtxo.poolTxid,
			})
			if err != nil {
				return nil, err
			}

			treeFromRound := round.GetRound().GetCongestionTree()
			congestionTree, err := toCongestionTree(treeFromRound)
			if err != nil {
				return nil, err
			}

			congestionTrees[vtxo.poolTxid] = congestionTree
		}

		redeemBranch, err := newRedeemBranch(ctx, explorer, congestionTrees[vtxo.poolTxid], vtxo)
		if err != nil {
			return nil, err
		}

		redeemBranches[vtxo.txid] = redeemBranch
	}

	return redeemBranches, nil
}
