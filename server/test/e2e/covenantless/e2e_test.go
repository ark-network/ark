package e2e_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	grpcclient "github.com/ark-network/ark/pkg/client-sdk/client/grpc"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/redemption"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	inmemorystoreconfig "github.com/ark-network/ark/pkg/client-sdk/store/inmemory"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	singlekeywallet "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey"
	inmemorystore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store/inmemory"
	utils "github.com/ark-network/ark/server/test/e2e"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/stretchr/testify/require"
)

const (
	composePath   = "../../../../docker-compose.clark.regtest.yml"
	redeemAddress = "bcrt1q2wrgf2hrkfegt0t97cnv4g5yvfjua9k6vua54d"
	aspUrl        = "http://localhost:7070"
)

func TestMain(m *testing.M) {
	_, err := utils.RunCommand("docker", "compose", "-f", composePath, "up", "-d", "--build")
	if err != nil {
		fmt.Printf("error starting docker-compose: %s", err)
		os.Exit(1)
	}

	time.Sleep(10 * time.Second)

	if err := utils.GenerateBlock(); err != nil {
		fmt.Printf("error generating block: %s", err)
		os.Exit(1)
	}

	if err := utils.SetupServerWalletCovenantless(aspUrl, 0.0); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	time.Sleep(3 * time.Second)

	_, err = runClarkCommand("init", "--server-url", "localhost:7070", "--password", utils.Password, "--network", "regtest", "--explorer", "http://chopsticks:3000")
	if err != nil {
		fmt.Printf("error initializing ark config: %s", err)
		os.Exit(1)
	}

	code := m.Run()

	_, err = utils.RunCommand("docker", "compose", "-f", composePath, "down", "-v")
	if err != nil {
		fmt.Printf("error stopping docker-compose: %s", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func TestSendOffchain(t *testing.T) {
	var receive utils.ArkReceive
	receiveStr, err := runClarkCommand("receive")
	require.NoError(t, err)

	err = json.Unmarshal([]byte(receiveStr), &receive)
	require.NoError(t, err)

	_, err = utils.RunCommand("nigiri", "faucet", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = runClarkCommand("settle", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	_, err = runClarkCommand("send", "--amount", "10000", "--to", receive.Offchain, "--password", utils.Password)
	require.NoError(t, err)

	var balance utils.ArkBalance
	balanceStr, err := runClarkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)

	_, err = runClarkCommand("settle", "--password", utils.Password)
	require.NoError(t, err)

	balanceStr, err = runClarkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)
}

func TestUnilateralExit(t *testing.T) {
	var receive utils.ArkReceive
	receiveStr, err := runClarkCommand("receive")
	require.NoError(t, err)

	err = json.Unmarshal([]byte(receiveStr), &receive)
	require.NoError(t, err)

	_, err = utils.RunCommand("nigiri", "faucet", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = runClarkCommand("settle", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	var balance utils.ArkBalance
	balanceStr, err := runClarkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)

	_, err = runClarkCommand("redeem", "--force", "--password", utils.Password)
	require.NoError(t, err)

	err = utils.GenerateBlock()
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	balanceStr, err = runClarkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.Zero(t, balance.Offchain.Total)
	require.Greater(t, len(balance.Onchain.Locked), 0)

	lockedBalance := balance.Onchain.Locked[0].Amount
	require.NotZero(t, lockedBalance)
}

func TestCollaborativeExit(t *testing.T) {
	var receive utils.ArkReceive
	receiveStr, err := runClarkCommand("receive")
	require.NoError(t, err)

	err = json.Unmarshal([]byte(receiveStr), &receive)
	require.NoError(t, err)

	_, err = utils.RunCommand("nigiri", "faucet", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = runClarkCommand("redeem", "--amount", "1000", "--address", redeemAddress, "--password", utils.Password)
	require.NoError(t, err)
}

func TestReactToRedemptionOfRefreshedVtxos(t *testing.T) {
	ctx := context.Background()
	client, grpcClient := setupArkSDK(t)
	defer grpcClient.Close()

	_, boardingAddress, err := client.Receive(ctx)
	require.NoError(t, err)

	_, err = utils.RunCommand("nigiri", "faucet", boardingAddress)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = client.Settle(ctx)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	_, err = client.Settle(ctx)
	require.NoError(t, err)

	_, spentVtxos, err := client.ListVtxos(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, spentVtxos)

	vtxo := spentVtxos[0]

	round, err := grpcClient.GetRound(ctx, vtxo.RoundTxid)
	require.NoError(t, err)

	expl := explorer.NewExplorer("http://localhost:3000", common.BitcoinRegTest)

	branch, err := redemption.NewCovenantlessRedeemBranch(expl, round.Tree, vtxo)
	require.NoError(t, err)

	txs, err := branch.RedeemPath()
	require.NoError(t, err)

	for _, tx := range txs {
		_, err := expl.Broadcast(tx)
		require.NoError(t, err)
	}

	// give time for the server to detect and process the fraud
	time.Sleep(20 * time.Second)

	balance, err := client.Balance(ctx, false)
	require.NoError(t, err)

	require.Empty(t, balance.OnchainBalance.LockedAmount)
}

func TestReactToRedemptionOfVtxosSpentOOR(t *testing.T) {
	ctx := context.Background()
	sdkClient, grpcClient := setupArkSDK(t)
	defer grpcClient.Close()

	offchainAddress, boardingAddress, err := sdkClient.Receive(ctx)
	require.NoError(t, err)

	_, err = utils.RunCommand("nigiri", "faucet", boardingAddress)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	roundId, err := sdkClient.Settle(ctx)
	require.NoError(t, err)

	err = utils.GenerateBlock()
	require.NoError(t, err)

	_, err = sdkClient.SendOffChain(ctx, false, []arksdk.Receiver{arksdk.NewBitcoinReceiver(offchainAddress, 1000)})
	require.NoError(t, err)

	_, err = sdkClient.Settle(ctx)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, spentVtxos, err := sdkClient.ListVtxos(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, spentVtxos)

	var vtxo client.Vtxo

	for _, v := range spentVtxos {
		if v.RoundTxid == roundId {
			vtxo = v
			break
		}
	}
	require.NotEmpty(t, vtxo)

	round, err := grpcClient.GetRound(ctx, vtxo.RoundTxid)
	require.NoError(t, err)

	expl := explorer.NewExplorer("http://localhost:3000", common.BitcoinRegTest)

	branch, err := redemption.NewCovenantlessRedeemBranch(expl, round.Tree, vtxo)
	require.NoError(t, err)

	txs, err := branch.RedeemPath()
	require.NoError(t, err)

	for _, tx := range txs {
		_, err := expl.Broadcast(tx)
		require.NoError(t, err)
	}

	// give time for the server to detect and process the fraud
	time.Sleep(50 * time.Second)

	balance, err := sdkClient.Balance(ctx, false)
	require.NoError(t, err)

	require.Empty(t, balance.OnchainBalance.LockedAmount)
}

func TestChainOutOfRoundTransactions(t *testing.T) {
	var receive utils.ArkReceive
	receiveStr, err := runClarkCommand("receive")
	require.NoError(t, err)

	err = json.Unmarshal([]byte(receiveStr), &receive)
	require.NoError(t, err)

	_, err = utils.RunCommand("nigiri", "faucet", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = runClarkCommand("settle", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	_, err = runClarkCommand("send", "--amount", "10000", "--to", receive.Offchain, "--password", utils.Password)
	require.NoError(t, err)

	var balance utils.ArkBalance
	balanceStr, err := runClarkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)

	_, err = runClarkCommand("send", "--amount", "10000", "--to", receive.Offchain, "--password", utils.Password)
	require.NoError(t, err)

	balanceStr, err = runClarkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)
}

func TestAliceSendsSeveralTimesToBob(t *testing.T) {
	ctx := context.Background()
	alice, grpcAlice := setupArkSDK(t)
	defer grpcAlice.Close()

	bob, grpcBob := setupArkSDK(t)
	defer grpcBob.Close()

	_, boardingAddress, err := alice.Receive(ctx)
	require.NoError(t, err)

	_, err = utils.RunCommand("nigiri", "faucet", boardingAddress)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = alice.Settle(ctx)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	bobAddress, _, err := bob.Receive(ctx)
	require.NoError(t, err)

	_, err = alice.SendOffChain(ctx, false, []arksdk.Receiver{arksdk.NewBitcoinReceiver(bobAddress, 1000)})
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	bobVtxos, _, err := bob.ListVtxos(ctx)
	require.NoError(t, err)
	require.Len(t, bobVtxos, 1)

	_, err = alice.SendOffChain(ctx, false, []arksdk.Receiver{arksdk.NewBitcoinReceiver(bobAddress, 10000)})
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	bobVtxos, _, err = bob.ListVtxos(ctx)
	require.NoError(t, err)
	require.Len(t, bobVtxos, 2)

	_, err = alice.SendOffChain(ctx, false, []arksdk.Receiver{arksdk.NewBitcoinReceiver(bobAddress, 10000)})
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	bobVtxos, _, err = bob.ListVtxos(ctx)
	require.NoError(t, err)
	require.Len(t, bobVtxos, 3)

	_, err = alice.SendOffChain(ctx, false, []arksdk.Receiver{arksdk.NewBitcoinReceiver(bobAddress, 10000)})
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	bobVtxos, _, err = bob.ListVtxos(ctx)
	require.NoError(t, err)
	require.Len(t, bobVtxos, 4)

	// bobVtxos should be unique
	uniqueVtxos := make(map[string]struct{})
	for _, v := range bobVtxos {
		uniqueVtxos[fmt.Sprintf("%s:%d", v.Txid, v.VOut)] = struct{}{}
	}
	require.Len(t, uniqueVtxos, 4)

	require.NoError(t, err)
}

func TestRedeemNotes(t *testing.T) {
	note := generateNote(t, 10_000)

	balanceBeforeStr, err := runClarkCommand("balance")
	require.NoError(t, err)

	var balanceBefore utils.ArkBalance
	require.NoError(t, json.Unmarshal([]byte(balanceBeforeStr), &balanceBefore))

	_, err = runClarkCommand("redeem-notes", "--notes", note)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	balanceAfterStr, err := runClarkCommand("balance")
	require.NoError(t, err)

	var balanceAfter utils.ArkBalance
	require.NoError(t, json.Unmarshal([]byte(balanceAfterStr), &balanceAfter))

	require.Greater(t, balanceAfter.Offchain.Total, balanceBefore.Offchain.Total)

	_, err = runClarkCommand("redeem-notes", "--notes", note)
	require.Error(t, err)
}

func TestSendToCLTVMultisigClosure(t *testing.T) {
	ctx := context.Background()
	alice, grpcAlice := setupArkSDK(t)
	defer grpcAlice.Close()

	bobPrivKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	configStore, err := inmemorystoreconfig.NewConfigStore()
	require.NoError(t, err)

	walletStore, err := inmemorystore.NewWalletStore()
	require.NoError(t, err)

	bobWallet, err := singlekeywallet.NewBitcoinWallet(
		configStore,
		walletStore,
	)
	require.NoError(t, err)

	_, err = bobWallet.Create(ctx, utils.Password, hex.EncodeToString(bobPrivKey.Serialize()))
	require.NoError(t, err)

	_, err = bobWallet.Unlock(ctx, utils.Password)
	require.NoError(t, err)

	bobPubKey := bobPrivKey.PubKey()

	// Fund Alice's account
	offchainAddr, boardingAddress, err := alice.Receive(ctx)
	require.NoError(t, err)

	aliceAddr, err := common.DecodeAddress(offchainAddr)
	require.NoError(t, err)

	_, err = utils.RunCommand("nigiri", "faucet", boardingAddress)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = alice.Settle(ctx)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	const cltvBlocks = 10
	const sendAmount = 10000

	currentHeight, err := utils.GetBlockHeight(false)
	require.NoError(t, err)

	vtxoScript := bitcointree.TapscriptsVtxoScript{
		TapscriptsVtxoScript: tree.TapscriptsVtxoScript{
			Closures: []tree.Closure{
				&tree.CLTVMultisigClosure{
					Locktime: common.Locktime{Type: common.LocktimeTypeBlock, Value: currentHeight + cltvBlocks},
					MultisigClosure: tree.MultisigClosure{
						PubKeys: []*secp256k1.PublicKey{bobPubKey},
					},
				},
			},
		},
	}

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]

	bobAddr := common.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Server:     aliceAddr.Server,
	}

	script, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(script).TapHash())
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	tapscript := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	bobAddrStr, err := bobAddr.Encode()
	require.NoError(t, err)

	redeemTx, err := alice.SendOffChain(ctx, false, []arksdk.Receiver{arksdk.NewBitcoinReceiver(bobAddrStr, sendAmount)})
	require.NoError(t, err)

	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(redeemTx), true)
	require.NoError(t, err)

	var bobOutput *wire.TxOut
	var bobOutputIndex uint32
	for i, out := range redeemPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(bobAddr.VtxoTapKey)) {
			bobOutput = out
			bobOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, bobOutput)

	time.Sleep(2 * time.Second)

	alicePkScript, err := common.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)

	ptx, err := bitcointree.BuildRedeemTx(
		[]common.VtxoInput{
			{
				Outpoint: &wire.OutPoint{
					Hash:  redeemPtx.UnsignedTx.TxHash(),
					Index: bobOutputIndex,
				},
				Tapscript:   tapscript,
				WitnessSize: closure.WitnessSize(),
				Amount:      bobOutput.Value,
			},
		},
		[]*wire.TxOut{
			{
				Value:    bobOutput.Value - 500,
				PkScript: alicePkScript,
			},
		},
	)
	require.NoError(t, err)

	signedTx, err := bobWallet.SignTransaction(
		ctx,
		explorer.NewExplorer("http://localhost:3000", common.BitcoinRegTest),
		ptx,
	)
	require.NoError(t, err)

	// should fail because the tx is not yet valid
	_, err = grpcAlice.SubmitRedeemTx(ctx, signedTx)
	require.Error(t, err)

	// Generate blocks to pass the timelock
	for i := 0; i < cltvBlocks+1; i++ {
		err = utils.GenerateBlock()
		require.NoError(t, err)
		time.Sleep(1 * time.Second)
	}

	_, err = grpcAlice.SubmitRedeemTx(ctx, signedTx)
	require.NoError(t, err)
}

func TestSweep(t *testing.T) {
	var receive utils.ArkReceive
	receiveStr, err := runClarkCommand("receive")
	require.NoError(t, err)

	err = json.Unmarshal([]byte(receiveStr), &receive)
	require.NoError(t, err)

	_, err = utils.RunCommand("nigiri", "faucet", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = runClarkCommand("settle", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	secretKey, pubkey, npub, err := utils.GetNostrKeys()
	require.NoError(t, err)

	_, err = runClarkCommand("register-nostr", "--profile", npub, "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	// connect to relay
	relay, err := nostr.RelayConnect(context.Background(), "ws://localhost:10547")
	require.NoError(t, err)
	defer relay.Close()

	sub, err := relay.Subscribe(context.Background(), nostr.Filters{
		{
			Kinds: []int{nostr.KindEncryptedDirectMessage},
		},
		{
			Tags: nostr.TagMap{
				"p": []string{pubkey},
			},
		},
	})
	require.NoError(t, err)
	defer sub.Close()

	_, err = utils.RunCommand("nigiri", "rpc", "generatetoaddress", "100", "bcrt1qe8eelqalnch946nzhefd5ajhgl2afjw5aegc59")
	require.NoError(t, err)

	time.Sleep(40 * time.Second)

	var balance utils.ArkBalance
	balanceStr, err := runClarkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.Zero(t, balance.Offchain.Total) // all funds should be swept

	var note string

	for event := range sub.Events {
		sharedSecret, err := nip04.ComputeSharedSecret(event.PubKey, secretKey)
		require.NoError(t, err)

		// Decrypt the NIP04 message
		decrypted, err := nip04.Decrypt(event.Content, sharedSecret)
		require.NoError(t, err)

		note = decrypted
		break // Exit after processing the first message
	}

	require.NotEmpty(t, note)

	// redeem the note
	_, err = runClarkCommand("redeem-notes", "--notes", note)
	require.NoError(t, err)
}

func runClarkCommand(arg ...string) (string, error) {
	args := append([]string{"ark"}, arg...)
	return utils.RunDockerExec("clarkd", args...)
}

func setupArkSDK(t *testing.T) (arksdk.ArkClient, client.TransportClient) {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType:  types.FileStore,
		AppDataStoreType: types.KVStore,
		BaseDir:          t.TempDir(),
	})
	require.NoError(t, err)

	client, err := arksdk.NewCovenantlessClient(appDataStore)
	require.NoError(t, err)

	err = client.Init(context.Background(), arksdk.InitArgs{
		WalletType: arksdk.SingleKeyWallet,
		ClientType: arksdk.GrpcClient,
		ServerUrl:  "localhost:7070",
		Password:   utils.Password,
	})
	require.NoError(t, err)

	err = client.Unlock(context.Background(), utils.Password)
	require.NoError(t, err)

	grpcClient, err := grpcclient.NewClient("localhost:7070")
	require.NoError(t, err)

	return client, grpcClient
}

func generateNote(t *testing.T, amount uint32) string {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	reqBody := bytes.NewReader([]byte(fmt.Sprintf(`{"amount": "%d"}`, amount)))
	req, err := http.NewRequest("POST", "http://localhost:7070/v1/admin/note", reqBody)
	if err != nil {
		t.Fatalf("failed to prepare note request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	resp, err := adminHttpClient.Do(req)
	if err != nil {
		t.Fatalf("failed to create note: %s", err)
	}

	var noteResp struct {
		Notes []string `json:"notes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&noteResp); err != nil {
		t.Fatalf("failed to parse response: %s", err)
	}

	return noteResp.Notes[0]
}
