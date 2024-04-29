package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
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
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
	"github.com/vulpemventures/go-elements/transaction"
	"golang.org/x/term"
)

const (
	DUST = 450
)

var passwordFlag = cli.StringFlag{
	Name:     "password",
	Usage:    "password to unlock the wallet",
	Required: false,
	Hidden:   true,
}

func hashPassword(password []byte) []byte {
	hash := sha256.Sum256(password)
	return hash[:]
}

func verifyPassword(password []byte) error {
	state, err := getState()
	if err != nil {
		return err
	}

	passwordHashString := state[PASSWORD_HASH]
	if len(passwordHashString) <= 0 {
		return fmt.Errorf("missing password hash")
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

func readPassword(ctx *cli.Context, verify bool) ([]byte, error) {
	password := []byte(ctx.String("password"))

	if len(password) == 0 {
		fmt.Print("unlock your wallet with password: ")
		var err error
		password, err = term.ReadPassword(int(syscall.Stdin))
		fmt.Println() // new line
		if err != nil {
			return nil, err
		}

	}

	if verify {
		if err := verifyPassword(password); err != nil {
			return nil, err
		}
	}

	return password, nil
}

func privateKeyFromPassword(ctx *cli.Context) (*secp256k1.PrivateKey, error) {
	state, err := getState()
	if err != nil {
		return nil, err
	}

	encryptedPrivateKeyString := state[ENCRYPTED_PRVKEY]
	if len(encryptedPrivateKeyString) <= 0 {
		return nil, fmt.Errorf("missing encrypted private key")
	}

	encryptedPrivateKey, err := hex.DecodeString(encryptedPrivateKeyString)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted private key: %s", err)
	}

	password, err := readPassword(ctx, true)
	if err != nil {
		return nil, err
	}
	fmt.Println("wallet unlocked")

	cypher := newAES128Cypher()
	privateKeyBytes, err := cypher.decrypt(encryptedPrivateKey, password)
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

	publicKeyString := state[PUBKEY]
	if len(publicKeyString) <= 0 {
		return nil, fmt.Errorf("missing public key")
	}

	publicKeyBytes, err := hex.DecodeString(publicKeyString)
	if err != nil {
		return nil, err
	}

	return secp256k1.ParsePubKey(publicKeyBytes)
}

func getAspPublicKey() (*secp256k1.PublicKey, error) {
	state, err := getState()
	if err != nil {
		return nil, err
	}

	arkPubKey := state[ASP_PUBKEY]
	if len(arkPubKey) <= 0 {
		return nil, fmt.Errorf("missing asp public key")
	}

	pubKeyBytes, err := hex.DecodeString(arkPubKey)
	if err != nil {
		return nil, err
	}

	return secp256k1.ParsePubKey(pubKeyBytes)
}

func getRoundLifetime() (int64, error) {
	state, err := getState()
	if err != nil {
		return -1, err
	}

	lifetime := state[ROUND_LIFETIME]
	if len(lifetime) <= 0 {
		return -1, fmt.Errorf("missing round lifetime")
	}

	roundLifetime, err := strconv.Atoi(lifetime)
	if err != nil {
		return -1, err
	}
	return int64(roundLifetime), nil
}

func getUnilateralExitDelay() (int64, error) {
	state, err := getState()
	if err != nil {
		return -1, err
	}

	delay := state[UNILATERAL_EXIT_DELAY]
	if len(delay) <= 0 {
		return -1, fmt.Errorf("missing unilateral exit delay")
	}

	redeemDelay, err := strconv.Atoi(delay)
	if err != nil {
		return -1, err
	}

	return int64(redeemDelay), nil
}

func coinSelect(vtxos []vtxo, amount uint64, sortByExpirationTime bool) ([]vtxo, uint64, error) {
	selected := make([]vtxo, 0)
	notSelected := make([]vtxo, 0)
	selectedAmount := uint64(0)

	if sortByExpirationTime {
		// sort vtxos by expiration (older first)
		sort.SliceStable(vtxos, func(i, j int) bool {
			if vtxos[i].expireAt == nil || vtxos[j].expireAt == nil {
				return false
			}

			return vtxos[i].expireAt.Before(*vtxos[j].expireAt)
		})
	}

	for _, vtxo := range vtxos {
		if selectedAmount >= amount {
			notSelected = append(notSelected, vtxo)
			break
		}

		selected = append(selected, vtxo)
		selectedAmount += vtxo.amount
	}

	if selectedAmount < amount {
		return nil, 0, fmt.Errorf("not enough funds to cover amount%d", amount)
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
	ctx context.Context, explorer Explorer, client arkv1.ArkServiceClient,
	addr string, computeExpiration bool,
) (uint64, map[int64]uint64, error) {
	amountByExpiration := make(map[int64]uint64, 0)

	vtxos, err := getVtxos(ctx, explorer, client, addr, computeExpiration)
	if err != nil {
		return 0, nil, err
	}
	var balance uint64
	for _, vtxo := range vtxos {
		balance += vtxo.amount

		if vtxo.expireAt != nil {
			expiration := vtxo.expireAt.Unix()

			if _, ok := amountByExpiration[expiration]; !ok {
				amountByExpiration[expiration] = 0
			}

			amountByExpiration[expiration] += vtxo.amount
		}
	}

	return balance, amountByExpiration, nil
}

func getBaseURL() (string, error) {
	state, err := getState()
	if err != nil {
		return "", err
	}

	baseURL := state[EXPLORER]
	if len(baseURL) <= 0 {
		return "", fmt.Errorf("missing explorer base url")
	}

	return baseURL, nil
}

func getTxBlocktime(txid string) (confirmed bool, blocktime int64, err error) {
	baseUrl, err := getBaseURL()
	if err != nil {
		return false, 0, err
	}
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

func getNetwork() (*common.Network, *network.Network) {
	state, err := getState()
	if err != nil {
		return &common.TestNet, &network.Testnet
	}

	net, ok := state[NETWORK]
	if !ok {
		return &common.Liquid, &network.Liquid
	}
	return networkFromString(net)
}

func networkFromString(net string) (*common.Network, *network.Network) {
	if net == "testnet" {
		return &common.TestNet, &network.Testnet
	}
	if net == "regtest" {
		return &common.RegTest, &network.Regtest
	}
	return &common.Liquid, &network.Liquid
}

func getAddress() (offchainAddr, onchainAddr, redemptionAddr string, err error) {
	userPubkey, err := getWalletPublicKey()
	if err != nil {
		return
	}

	aspPubkey, err := getAspPublicKey()
	if err != nil {
		return
	}

	unilateralExitDelay, err := getUnilateralExitDelay()
	if err != nil {
		return
	}

	arkNet, liquidNet := getNetwork()

	arkAddr, err := common.EncodeAddress(arkNet.Addr, userPubkey, aspPubkey)
	if err != nil {
		return
	}

	p2wpkh := payment.FromPublicKey(userPubkey, liquidNet, nil)
	liquidAddr, err := p2wpkh.WitnessPubKeyHash()
	if err != nil {
		return
	}

	vtxoTapKey, _, err := computeVtxoTaprootScript(
		userPubkey, aspPubkey, uint(unilateralExitDelay),
	)
	if err != nil {
		return
	}

	_, net := getNetwork()

	payment, err := payment.FromTweakedKey(vtxoTapKey, net, nil)
	if err != nil {
		return
	}

	redemptionAddr, err = payment.TaprootAddress()
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
	ctx context.Context, client arkv1.ArkServiceClient, paymentID string,
	vtxosToSign []vtxo, secKey *secp256k1.PrivateKey, receivers []*arkv1.Output,
) (poolTxID string, err error) {
	stream, err := client.GetEventStream(ctx, &arkv1.GetEventStreamRequest{})
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

		if e := event.GetRoundFailed(); e != nil {
			pingStop()
			return "", fmt.Errorf("round failed: %s", e.GetReason())
		}

		if e := event.GetRoundFinalization(); e != nil {
			// stop pinging as soon as we receive some forfeit txs
			pingStop()
			fmt.Println("round finalization started")

			poolTx := e.GetPoolTx()
			ptx, err := psetv2.NewPsetFromBase64(poolTx)
			if err != nil {
				return "", err
			}

			congestionTree, err := toCongestionTree(e.GetCongestionTree())
			if err != nil {
				return "", err
			}

			connectors := e.GetConnectors()

			aspPubkey, err := getAspPublicKey()
			if err != nil {
				return "", err
			}

			roundLifetime, err := getRoundLifetime()
			if err != nil {
				return "", err
			}

			if !isOnchainOnly(receivers) {
				// validate the congestion tree
				if err := tree.ValidateCongestionTree(
					congestionTree, poolTx, aspPubkey, int64(roundLifetime),
				); err != nil {
					return "", err
				}
			}

			if err := common.ValidateConnectors(poolTx, connectors); err != nil {
				return "", err
			}

			unilateralExitDelay, err := getUnilateralExitDelay()
			if err != nil {
				return "", err
			}

			for _, receiver := range receivers {
				isOnChain, onchainScript, userPubkey, err := decodeReceiverAddress(
					receiver.Address,
				)
				if err != nil {
					return "", err
				}

				if isOnChain {
					// collaborative exit case
					// search for the output in the pool tx
					found := false
					for _, output := range ptx.Outputs {
						if bytes.Equal(output.Script, onchainScript) {
							if output.Value != receiver.Amount {
								return "", fmt.Errorf(
									"invalid collaborative exit output amount: got %d, want %d",
									output.Value, receiver.Amount,
								)
							}

							found = true
							break
						}
					}

					if !found {
						return "", fmt.Errorf(
							"collaborative exit output not found: %s", receiver.Address,
						)
					}

					continue
				}

				// off-chain send case
				// search for the output in congestion tree
				found := false

				// compute the receiver output taproot key
				outputTapKey, _, err := computeVtxoTaprootScript(
					userPubkey, aspPubkey, uint(unilateralExitDelay),
				)
				if err != nil {
					return "", err
				}

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
						if bytes.Equal(
							output.Script[2:], schnorr.SerializePubKey(outputTapKey),
						) {
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
					return "", fmt.Errorf(
						"off-chain send output not found: %s", receiver.Address,
					)
				}
			}

			fmt.Println("congestion tree validated")

			forfeits := e.GetForfeitTxs()
			signedForfeits := make([]string, 0)

			fmt.Print("signing forfeit txs... ")

			explorer := NewExplorer()

			connectorsTxids := make([]string, 0, len(connectors))
			for _, connector := range connectors {
				p, _ := psetv2.NewPsetFromBase64(connector)
				utx, _ := p.UnsignedTx()
				txid := utx.TxHash().String()

				connectorsTxids = append(connectorsTxids, txid)
			}

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
							// verify that the connector is in the connectors list
							connectorTxid := chainhash.Hash(pset.Inputs[0].PreviousTxid).String()
							connectorFound := false
							for _, txid := range connectorsTxids {
								if txid == connectorTxid {
									connectorFound = true
									break
								}
							}

							if !connectorFound {
								return "", fmt.Errorf("connector txid %s not found in the connectors list", connectorTxid)
							}

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
			_, err = client.FinalizePayment(ctx, &arkv1.FinalizePaymentRequest{
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
func ping(
	ctx context.Context, client arkv1.ArkServiceClient, req *arkv1.PingRequest,
) func() {
	_, err := client.Ping(ctx, req)
	if err != nil {
		return nil
	}

	ticker := time.NewTicker(5 * time.Second)

	go func(t *time.Ticker) {
		for range t.C {
			// nolint
			client.Ping(ctx, req)
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

// castCongestionTree converts a tree.CongestionTree to a repeated arkv1.TreeLevel
func castCongestionTree(congestionTree tree.CongestionTree) *arkv1.Tree {
	levels := make([]*arkv1.TreeLevel, 0, len(congestionTree))
	for _, level := range congestionTree {
		levelProto := &arkv1.TreeLevel{
			Nodes: make([]*arkv1.Node, 0, len(level)),
		}

		for _, node := range level {
			levelProto.Nodes = append(levelProto.Nodes, &arkv1.Node{
				Txid:       node.Txid,
				Tx:         node.Tx,
				ParentTxid: node.ParentTxid,
			})
		}

		levels = append(levels, levelProto)
	}
	return &arkv1.Tree{
		Levels: levels,
	}
}

func decodeReceiverAddress(addr string) (
	bool, []byte, *secp256k1.PublicKey, error,
) {
	outputScript, err := address.ToOutputScript(addr)
	if err != nil {
		_, userPubkey, _, err := common.DecodeAddress(addr)
		if err != nil {
			return false, nil, nil, err
		}
		return false, nil, userPubkey, nil
	}

	return true, outputScript, nil, nil
}

func findSweepClosure(
	congestionTree tree.CongestionTree,
) (*taproot.TapElementsLeaf, uint, error) {
	root, err := congestionTree.Root()
	if err != nil {
		return nil, 0, err
	}

	// find the sweep closure
	tx, err := psetv2.NewPsetFromBase64(root.Tx)
	if err != nil {
		return nil, 0, err
	}

	var seconds uint
	var sweepClosure *taproot.TapElementsLeaf
	for _, tapLeaf := range tx.Inputs[0].TapLeafScript {
		closure := &tree.CSVSigClosure{}
		valid, err := closure.Decode(tapLeaf.Script)
		if err != nil {
			continue
		}

		if valid && closure.Seconds > seconds {
			seconds = closure.Seconds
			sweepClosure = &tapLeaf.TapElementsLeaf
		}
	}

	if sweepClosure == nil {
		return nil, 0, fmt.Errorf("sweep closure not found")
	}

	return sweepClosure, seconds, nil
}

func getRedeemBranches(
	ctx context.Context, explorer Explorer, client arkv1.ArkServiceClient,
	vtxos []vtxo,
) (map[string]*redeemBranch, error) {
	congestionTrees := make(map[string]tree.CongestionTree, 0)
	redeemBranches := make(map[string]*redeemBranch, 0)

	for _, vtxo := range vtxos {
		if _, ok := congestionTrees[vtxo.poolTxid]; !ok {
			round, err := client.GetRound(ctx, &arkv1.GetRoundRequest{
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

		redeemBranch, err := newRedeemBranch(
			explorer, congestionTrees[vtxo.poolTxid], vtxo,
		)
		if err != nil {
			return nil, err
		}

		redeemBranches[vtxo.txid] = redeemBranch
	}

	return redeemBranches, nil
}

func computeVtxoTaprootScript(
	userPubkey, aspPubkey *secp256k1.PublicKey, exitDelay uint,
) (*secp256k1.PublicKey, *taproot.TapscriptElementsProof, error) {
	redeemClosure := &tree.CSVSigClosure{
		Pubkey:  userPubkey,
		Seconds: exitDelay,
	}

	forfeitClosure := &tree.ForfeitClosure{
		Pubkey:    userPubkey,
		AspPubkey: aspPubkey,
	}

	redeemLeaf, err := redeemClosure.Leaf()
	if err != nil {
		return nil, nil, err
	}

	forfeitLeaf, err := forfeitClosure.Leaf()
	if err != nil {
		return nil, nil, err
	}

	vtxoTaprootTree := taproot.AssembleTaprootScriptTree(
		*redeemLeaf, *forfeitLeaf,
	)
	root := vtxoTaprootTree.RootNode.TapHash()

	unspendableKey := tree.UnspendableKey()
	vtxoTaprootKey := taproot.ComputeTaprootOutputKey(unspendableKey, root[:])

	redeemLeafHash := redeemLeaf.TapHash()
	proofIndex := vtxoTaprootTree.LeafProofIndex[redeemLeafHash]
	proof := vtxoTaprootTree.LeafMerkleProofs[proofIndex]

	return vtxoTaprootKey, &proof, nil
}

func addVtxoInput(
	updater *psetv2.Updater, inputArgs psetv2.InputArgs, exitDelay uint,
	tapLeafProof *taproot.TapscriptElementsProof,
) error {
	sequence, err := common.BIP68EncodeAsNumber(exitDelay)
	if err != nil {
		return nil
	}

	nextInputIndex := len(updater.Pset.Inputs)
	if err := updater.AddInputs([]psetv2.InputArgs{inputArgs}); err != nil {
		return err
	}

	updater.Pset.Inputs[nextInputIndex].Sequence = sequence

	return updater.AddInTapLeafScript(
		nextInputIndex,
		psetv2.NewTapLeafScript(
			*tapLeafProof,
			tree.UnspendableKey(),
		),
	)
}

func coinSelectOnchain(
	explorer Explorer, targetAmount uint64, exclude []utxo,
) ([]utxo, []utxo, uint64, error) {
	_, onchainAddr, _, err := getAddress()
	if err != nil {
		return nil, nil, 0, err
	}

	fromExplorer, err := explorer.GetUtxos(onchainAddr)
	if err != nil {
		return nil, nil, 0, err
	}

	utxos := make([]utxo, 0)
	selectedAmount := uint64(0)
	for _, utxo := range fromExplorer {
		if selectedAmount >= targetAmount {
			break
		}

		for _, excluded := range exclude {
			if utxo.Txid == excluded.Txid && utxo.Vout == excluded.Vout {
				continue
			}
		}

		utxos = append(utxos, utxo)
		selectedAmount += utxo.Amount
	}

	if selectedAmount >= targetAmount {
		return utxos, nil, selectedAmount - targetAmount, nil
	}

	userPubkey, err := getWalletPublicKey()
	if err != nil {
		return nil, nil, 0, err
	}

	aspPubkey, err := getAspPublicKey()
	if err != nil {
		return nil, nil, 0, err
	}

	unilateralExitDelay, err := getUnilateralExitDelay()
	if err != nil {
		return nil, nil, 0, err
	}

	vtxoTapKey, _, err := computeVtxoTaprootScript(
		userPubkey, aspPubkey, uint(unilateralExitDelay),
	)
	if err != nil {
		return nil, nil, 0, err
	}

	_, net := getNetwork()

	pay, err := payment.FromTweakedKey(vtxoTapKey, net, nil)
	if err != nil {
		return nil, nil, 0, err
	}

	addr, err := pay.TaprootAddress()
	if err != nil {
		return nil, nil, 0, err
	}

	fromExplorer, err = explorer.GetUtxos(addr)
	if err != nil {
		return nil, nil, 0, err
	}

	delayedUtxos := make([]utxo, 0)
	for _, utxo := range fromExplorer {
		if selectedAmount >= targetAmount {
			break
		}

		availableAt := time.Unix(utxo.Status.Blocktime, 0).Add(
			time.Duration(unilateralExitDelay) * time.Second,
		)
		if availableAt.After(time.Now()) {
			continue
		}

		for _, excluded := range exclude {
			if utxo.Txid == excluded.Txid && utxo.Vout == excluded.Vout {
				continue
			}
		}

		delayedUtxos = append(delayedUtxos, utxo)
		selectedAmount += utxo.Amount
	}

	if selectedAmount < targetAmount {
		return nil, nil, 0, fmt.Errorf(
			"not enough funds to cover amount %d", targetAmount,
		)
	}

	return utxos, delayedUtxos, selectedAmount - targetAmount, nil
}

func addInputs(
	updater *psetv2.Updater, utxos, delayedUtxos []utxo, net *network.Network,
) error {
	_, onchainAddr, _, err := getAddress()
	if err != nil {
		return err
	}

	changeScript, err := address.ToOutputScript(onchainAddr)
	if err != nil {
		return err
	}

	for _, utxo := range utxos {
		if err := updater.AddInputs([]psetv2.InputArgs{
			{
				Txid:    utxo.Txid,
				TxIndex: utxo.Vout,
			},
		}); err != nil {
			return err
		}

		assetID, err := elementsutil.AssetHashToBytes(utxo.Asset)
		if err != nil {
			return err
		}

		value, err := elementsutil.ValueToBytes(utxo.Amount)
		if err != nil {
			return err
		}

		witnessUtxo := transaction.TxOutput{
			Asset:  assetID,
			Value:  value,
			Script: changeScript,
			Nonce:  []byte{0x00},
		}

		if err := updater.AddInWitnessUtxo(
			len(updater.Pset.Inputs)-1, &witnessUtxo,
		); err != nil {
			return err
		}
	}

	if len(delayedUtxos) > 0 {
		userPubkey, err := getWalletPublicKey()
		if err != nil {
			return err
		}

		aspPubkey, err := getAspPublicKey()
		if err != nil {
			return err
		}

		unilateralExitDelay, err := getUnilateralExitDelay()
		if err != nil {
			return err
		}

		vtxoTapKey, leafProof, err := computeVtxoTaprootScript(
			userPubkey, aspPubkey, uint(unilateralExitDelay),
		)
		if err != nil {
			return err
		}

		pay, err := payment.FromTweakedKey(vtxoTapKey, net, nil)
		if err != nil {
			return err
		}

		addr, err := pay.TaprootAddress()
		if err != nil {
			return err
		}

		script, err := address.ToOutputScript(addr)
		if err != nil {
			return err
		}

		for _, utxo := range delayedUtxos {
			if err := addVtxoInput(
				updater,
				psetv2.InputArgs{
					Txid:    utxo.Txid,
					TxIndex: utxo.Vout,
				},
				uint(unilateralExitDelay),
				leafProof,
			); err != nil {
				return err
			}

			assetID, err := elementsutil.AssetHashToBytes(utxo.Asset)
			if err != nil {
				return err
			}

			value, err := elementsutil.ValueToBytes(utxo.Amount)
			if err != nil {
				return err
			}

			witnessUtxo := transaction.NewTxOutput(assetID, value, script)

			if err := updater.AddInWitnessUtxo(
				len(updater.Pset.Inputs)-1, witnessUtxo,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

func isOnchainOnly(receivers []*arkv1.Output) bool {
	for _, receiver := range receivers {
		isOnChain, _, _, err := decodeReceiverAddress(receiver.Address)
		if err != nil {
			continue
		}

		if !isOnChain {
			return false
		}
	}

	return true
}
