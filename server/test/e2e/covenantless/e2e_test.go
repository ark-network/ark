package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/ark-network/ark/common"
	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	grpcclient "github.com/ark-network/ark/pkg/client-sdk/client/grpc"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/redemption"
	inmemorystore "github.com/ark-network/ark/pkg/client-sdk/store/inmemory"
	utils "github.com/ark-network/ark/server/test/e2e"
	"github.com/stretchr/testify/require"
)

const (
	composePath   = "../../../../docker-compose.clark.regtest.yml"
	redeemAddress = "bcrt1q2wrgf2hrkfegt0t97cnv4g5yvfjua9k6vua54d"
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

	if err := setupAspWallet(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	time.Sleep(3 * time.Second)

	_, err = runClarkCommand("init", "--asp-url", "localhost:7070", "--password", utils.Password, "--network", "regtest", "--explorer", "http://chopsticks:3000")
	if err != nil {
		fmt.Printf("error initializing ark config: %s", err)
		os.Exit(1)
	}

	code := m.Run()

	_, err = utils.RunCommand("docker", "compose", "-f", composePath, "down")
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

	_, err = runClarkCommand("claim", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	_, err = runClarkCommand("send", "--amount", "10000", "--to", receive.Offchain, "--password", utils.Password)
	require.NoError(t, err)

	var balance utils.ArkBalance
	balanceStr, err := runClarkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)

	_, err = runClarkCommand("claim", "--password", utils.Password)
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

	_, err = runClarkCommand("claim", "--password", utils.Password)
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

	_, err = runClarkCommand("claim", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	_, err = runClarkCommand("redeem", "--amount", "1000", "--address", redeemAddress, "--password", utils.Password)
	require.NoError(t, err)
}

func TestReactToSpentVtxosRedemption(t *testing.T) {
	ctx := context.Background()
	client, grpcClient := setupArkSDK(t)
	defer grpcClient.Close()

	offchainAddress, boardingAddress, err := client.Receive(ctx)
	require.NoError(t, err)

	_, err = utils.RunCommand("nigiri", "faucet", boardingAddress)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = client.Claim(ctx)
	require.NoError(t, err)

	_, err = client.SendOffChain(ctx, false, []arksdk.Receiver{arksdk.NewBitcoinReceiver(offchainAddress, 1000)})
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

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

	// give time for the ASP to detect and process the fraud
	time.Sleep(20 * time.Second)

	balance, err := client.Balance(ctx, false)
	require.NoError(t, err)

	require.Empty(t, balance.OnchainBalance.LockedAmount)
}

func TestReactToAsyncSpentVtxosRedemption(t *testing.T) {
	t.Run("receiver claimed funds", func(t *testing.T) {
		ctx := context.Background()
		sdkClient, grpcClient := setupArkSDK(t)
		defer grpcClient.Close()

		offchainAddress, boardingAddress, err := sdkClient.Receive(ctx)
		require.NoError(t, err)

		_, err = utils.RunCommand("nigiri", "faucet", boardingAddress)
		require.NoError(t, err)

		time.Sleep(5 * time.Second)

		roundId, err := sdkClient.Claim(ctx)
		require.NoError(t, err)

		err = utils.GenerateBlock()
		require.NoError(t, err)

		_, err = sdkClient.SendAsync(ctx, false, []arksdk.Receiver{arksdk.NewBitcoinReceiver(offchainAddress, 1000)})
		require.NoError(t, err)

		_, err = sdkClient.Claim(ctx)
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

		// give time for the ASP to detect and process the fraud
		time.Sleep(50 * time.Second)

		balance, err := sdkClient.Balance(ctx, false)
		require.NoError(t, err)

		require.Empty(t, balance.OnchainBalance.LockedAmount)
	})
}

func TestAliceSeveralPaymentsToBob(t *testing.T) {
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

	_, err = alice.Claim(ctx)
	require.NoError(t, err)

	bobAddress, _, err := bob.Receive(ctx)
	require.NoError(t, err)

	_, err = alice.SendOffChain(ctx, false, []arksdk.Receiver{arksdk.NewBitcoinReceiver(bobAddress, 1000)})
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	bobVtxos, _, err := bob.ListVtxos(ctx)
	require.NoError(t, err)
	require.Len(t, bobVtxos, 1)

	_, err = bob.Claim(ctx)
	require.NoError(t, err)

	_, err = alice.Claim(ctx)
	require.NoError(t, err)

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

	_, err = alice.SendAsync(ctx, false, []arksdk.Receiver{arksdk.NewBitcoinReceiver(bobAddress, 10000)})
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	bobVtxos, _, err = bob.ListVtxos(ctx)
	require.NoError(t, err)
	require.Len(t, bobVtxos, 4)

	_, err = alice.Claim(ctx)
	require.NoError(t, err)

	// bobVtxos should be unique
	uniqueVtxos := make(map[string]struct{})
	for _, v := range bobVtxos {
		uniqueVtxos[fmt.Sprintf("%s:%d", v.Txid, v.VOut)] = struct{}{}
	}
	require.Len(t, uniqueVtxos, 4)

	_, err = bob.Claim(ctx)
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

	_, err = runClarkCommand("claim", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	_, err = utils.RunCommand("nigiri", "rpc", "generatetoaddress", "100", "bcrt1qe8eelqalnch946nzhefd5ajhgl2afjw5aegc59")
	require.NoError(t, err)

	time.Sleep(40 * time.Second)

	var balance utils.ArkBalance
	balanceStr, err := runClarkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.Zero(t, balance.Offchain.Total) // all funds should be swept
}

func runClarkCommand(arg ...string) (string, error) {
	args := append([]string{"exec", "-t", "clarkd", "ark"}, arg...)
	return utils.RunCommand("docker", args...)
}

func setupAspWallet() error {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequest("GET", "http://localhost:7070/v1/admin/wallet/seed", nil)
	if err != nil {
		return fmt.Errorf("failed to prepare generate seed request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")

	seedResp, err := adminHttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to generate seed: %s", err)
	}

	var seed struct {
		Seed string `json:"seed"`
	}

	if err := json.NewDecoder(seedResp.Body).Decode(&seed); err != nil {
		return fmt.Errorf("failed to parse response: %s", err)
	}

	reqBody := bytes.NewReader([]byte(fmt.Sprintf(`{"seed": "%s", "password": "%s"}`, seed.Seed, utils.Password)))
	req, err = http.NewRequest("POST", "http://localhost:7070/v1/admin/wallet/create", reqBody)
	if err != nil {
		return fmt.Errorf("failed to prepare wallet create request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	if _, err := adminHttpClient.Do(req); err != nil {
		return fmt.Errorf("failed to create wallet: %s", err)
	}

	reqBody = bytes.NewReader([]byte(fmt.Sprintf(`{"password": "%s"}`, utils.Password)))
	req, err = http.NewRequest("POST", "http://localhost:7070/v1/admin/wallet/unlock", reqBody)
	if err != nil {
		return fmt.Errorf("failed to prepare wallet unlock request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	if _, err := adminHttpClient.Do(req); err != nil {
		return fmt.Errorf("failed to unlock wallet: %s", err)
	}

	time.Sleep(time.Second)

	req, err = http.NewRequest("GET", "http://localhost:7070/v1/admin/wallet/address", nil)
	if err != nil {
		return fmt.Errorf("failed to prepare new address request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")

	resp, err := adminHttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get new address: %s", err)
	}

	var addr struct {
		Address string `json:"address"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&addr); err != nil {
		return fmt.Errorf("failed to parse response: %s", err)
	}

	const numberOfFaucet = 15 // must cover the liquidity needed for all tests

	for i := 0; i < numberOfFaucet; i++ {
		_, err = utils.RunCommand("nigiri", "faucet", addr.Address)
		if err != nil {
			return fmt.Errorf("failed to fund wallet: %s", err)
		}
	}

	time.Sleep(5 * time.Second)
	return nil
}

func setupArkSDK(t *testing.T) (arksdk.ArkClient, client.ASPClient) {
	storeSvc, err := inmemorystore.NewConfigStore()
	require.NoError(t, err)

	client, err := arksdk.NewCovenantlessClient(storeSvc)
	require.NoError(t, err)

	err = client.Init(context.Background(), arksdk.InitArgs{
		WalletType: arksdk.SingleKeyWallet,
		ClientType: arksdk.GrpcClient,
		AspUrl:     "localhost:7070",
		Password:   utils.Password,
	})
	require.NoError(t, err)

	err = client.Unlock(context.Background(), utils.Password)
	require.NoError(t, err)

	grpcClient, err := grpcclient.NewClient("localhost:7070")
	require.NoError(t, err)

	return client, grpcClient
}
