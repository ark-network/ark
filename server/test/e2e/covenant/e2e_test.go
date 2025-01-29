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
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	utils "github.com/ark-network/ark/server/test/e2e"
	"github.com/stretchr/testify/require"
)

const (
	composePath = "../../../../docker-compose.regtest.yml"
	ONE_BTC     = 1_0000_0000
	redeemAddr  = "ert1p7hffs7y50jy8l34g334yke9cntzahml40xm2hx90g34jq8mqu7zsezhwcc"
)

func TestMain(m *testing.M) {
	_, err := utils.RunCommand("docker", "compose", "-f", composePath, "up", "-d", "--build")
	if err != nil {
		fmt.Printf("error starting docker-compose: %s", err)
		os.Exit(1)
	}

	fmt.Println("waiting for docker containers to start...")

	time.Sleep(10 * time.Second)

	if err := setupServerWallet(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	time.Sleep(3 * time.Second)

	_, err = runArkCommand("init", "--server-url", "localhost:6060", "--password", utils.Password, "--network", common.LiquidRegTest.Name, "--explorer", "http://chopsticks-liquid:3000")
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
	receiveStr, err := runArkCommand("receive")
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal([]byte(receiveStr), &receive))

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = runArkCommand("settle", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	_, err = runArkCommand("send", "--amount", "1000", "--to", receive.Offchain, "--password", utils.Password)
	require.NoError(t, err)

	var balance utils.ArkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)
}

func TestUnilateralExit(t *testing.T) {
	var receive utils.ArkReceive
	receiveStr, err := runArkCommand("receive")
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal([]byte(receiveStr), &receive))

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = runArkCommand("settle", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	var balance utils.ArkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)

	_, err = runArkCommand("redeem", "--force", "--password", utils.Password)
	require.NoError(t, err)

	err = utils.GenerateBlock()
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	balanceStr, err = runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.Zero(t, balance.Offchain.Total)
	require.Greater(t, len(balance.Onchain.Locked), 0)

	lockedBalance := balance.Onchain.Locked[0].Amount
	require.NotZero(t, lockedBalance)
}

func TestCollaborativeExit(t *testing.T) {
	var receive utils.ArkReceive
	receiveStr, err := runArkCommand("receive")
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal([]byte(receiveStr), &receive))

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = runArkCommand("settle", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	_, err = runArkCommand("redeem", "--amount", "10000", "--address", redeemAddr, "--password", utils.Password)
	require.NoError(t, err)
}

func TestReactToSpentVtxosRedemption(t *testing.T) {
	ctx := context.Background()
	client, grpcClient := setupArkSDK(t)
	defer grpcClient.Close()

	offchainAddress, boardingAddress, err := client.Receive(ctx)
	require.NoError(t, err)

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", boardingAddress)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = client.Settle(ctx)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	spendable, _, err := client.ListVtxos(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, spendable)

	vtxo := spendable[0]

	_, err = client.SendOffChain(ctx, false, []arksdk.Receiver{arksdk.NewLiquidReceiver(offchainAddress, 1000)}, false)
	require.NoError(t, err)

	round, err := grpcClient.GetRound(ctx, vtxo.RoundTxid)
	require.NoError(t, err)

	expl := explorer.NewExplorer("http://localhost:3001", common.LiquidRegTest)

	branch, err := redemption.NewCovenantRedeemBranch(expl, round.Tree, vtxo)
	require.NoError(t, err)

	txs, err := branch.RedeemPath()
	require.NoError(t, err)

	for _, tx := range txs {
		_, err := expl.Broadcast(tx)
		require.NoError(t, err)
	}

	// give time for the server to detect and process the fraud
	time.Sleep(18 * time.Second)

	balance, err := client.Balance(ctx, true)
	require.NoError(t, err)

	require.Empty(t, balance.OnchainBalance.LockedAmount)
}

func TestSweep(t *testing.T) {
	var receive utils.ArkReceive
	receiveStr, err := runArkCommand("receive")
	require.NoError(t, err)

	err = json.Unmarshal([]byte(receiveStr), &receive)
	require.NoError(t, err)

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = runArkCommand("settle", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	_, err = utils.RunCommand("nigiri", "rpc", "--liquid", "generatetoaddress", "100", "el1qqwk722tghgkgmh3r2ph4d2apwj0dy9xnzlenzklx8jg3z299fpaw56trre9gpk6wmw0u4qycajqeva3t7lzp7wnacvwxha59r")
	require.NoError(t, err)

	time.Sleep(40 * time.Second)

	var balance utils.ArkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.Zero(t, balance.Offchain.Total) // all funds should be swept
}

func runArkCommand(arg ...string) (string, error) {
	args := append([]string{"exec", "-t", "arkd", "ark"}, arg...)
	return utils.RunCommand("docker", args...)
}

func setupServerWallet() error {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequest("GET", "http://localhost:6060/v1/admin/wallet/seed", nil)
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
	req, err = http.NewRequest("POST", "http://localhost:6060/v1/admin/wallet/create", reqBody)
	if err != nil {
		return fmt.Errorf("failed to prepare wallet create request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	if _, err := adminHttpClient.Do(req); err != nil {
		return fmt.Errorf("failed to create wallet: %s", err)
	}

	reqBody = bytes.NewReader([]byte(fmt.Sprintf(`{"password": "%s"}`, utils.Password)))
	req, err = http.NewRequest("POST", "http://localhost:6060/v1/admin/wallet/unlock", reqBody)
	if err != nil {
		return fmt.Errorf("failed to prepare wallet unlock request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	if _, err := adminHttpClient.Do(req); err != nil {
		return fmt.Errorf("failed to unlock wallet: %s", err)
	}

	time.Sleep(time.Second)

	req, err = http.NewRequest("GET", "http://localhost:6060/v1/admin/wallet/address", nil)
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

	const numberOfFaucet = 6

	for i := 0; i < numberOfFaucet; i++ {
		if _, err := utils.RunCommand("nigiri", "faucet", "--liquid", addr.Address); err != nil {
			return fmt.Errorf("failed to fund wallet: %s with address %s", err, addr.Address)
		}
	}

	time.Sleep(5 * time.Second)

	return nil
}

func setupArkSDK(t *testing.T) (arksdk.ArkClient, client.TransportClient) {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType:  types.FileStore,
		AppDataStoreType: types.KVStore,
		BaseDir:          t.TempDir(),
	})
	require.NoError(t, err)

	client, err := arksdk.NewCovenantClient(appDataStore)
	require.NoError(t, err)

	err = client.Init(context.Background(), arksdk.InitArgs{
		WalletType: arksdk.SingleKeyWallet,
		ClientType: arksdk.GrpcClient,
		ServerUrl:  "localhost:6060",
		Password:   utils.Password,
	})
	require.NoError(t, err)

	err = client.Unlock(context.Background(), utils.Password)
	require.NoError(t, err)

	grpcClient, err := grpcclient.NewClient("localhost:6060")
	require.NoError(t, err)

	return client, grpcClient
}
