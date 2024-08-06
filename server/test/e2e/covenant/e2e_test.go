package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/ark-network/ark/common"
	utils "github.com/ark-network/ark/test/e2e"
	"github.com/stretchr/testify/require"
)

const (
	composePath = "../../../../docker-compose.regtest.yml"
	ONE_BTC     = 1_0000_0000
)

func TestMain(m *testing.M) {
	_, err := utils.RunCommand("docker", "compose", "-f", composePath, "up", "-d", "--build")
	if err != nil {
		fmt.Printf("error starting docker-compose: %s", err)
		os.Exit(1)
	}

	time.Sleep(10 * time.Second)

	if err := setupAspWallet(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	time.Sleep(3 * time.Second)

	_, err = runArkCommand("init", "--ark-url", "localhost:8080", "--password", utils.Password, "--network", common.LiquidRegTest.Name, "--explorer", "http://chopsticks-liquid:3000")
	if err != nil {
		fmt.Printf("error initializing ark config: %s", err)
		os.Exit(1)
	}

	var receive utils.ArkReceive
	receiveStr, err := runArkCommand("receive")
	if err != nil {
		fmt.Printf("error getting ark receive addresses: %s", err)
		os.Exit(1)
	}

	if err := json.Unmarshal([]byte(receiveStr), &receive); err != nil {
		fmt.Printf("error unmarshalling ark receive addresses: %s", err)
		os.Exit(1)
	}

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", receive.Onchain)
	if err != nil {
		fmt.Printf("error funding ark account: %s", err)
		os.Exit(1)
	}

	time.Sleep(5 * time.Second)

	code := m.Run()

	_, err = utils.RunCommand("docker", "compose", "-f", composePath, "down")
	if err != nil {
		fmt.Printf("error stopping docker-compose: %s", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func TestOnboard(t *testing.T) {
	var balance utils.ArkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	balanceBefore := balance.Offchain.Total

	_, err = runArkCommand("onboard", "--amount", "1000", "--password", utils.Password)
	require.NoError(t, err)
	err = utils.GenerateBlock()
	require.NoError(t, err)

	balanceStr, err = runArkCommand("balance")
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.Equal(t, balanceBefore+1000, balance.Offchain.Total)
}

func TestTrustedOnboard(t *testing.T) {
	var balance utils.ArkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	balanceBefore := balance.Offchain.Total

	onboardStr, err := runArkCommand("onboard", "--trusted", "--password", utils.Password)
	require.NoError(t, err)

	var result utils.ArkTrustedOnboard
	require.NoError(t, json.Unmarshal([]byte(onboardStr), &result))

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", result.OnboardAddress)
	require.NoError(t, err)

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", result.OnboardAddress)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	balanceStr, err = runArkCommand("balance")
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.Equal(t, balanceBefore+(2*(ONE_BTC-30)), balance.Offchain.Total)
}

func TestSendOffchain(t *testing.T) {
	_, err := runArkCommand("onboard", "--amount", "1000", "--password", utils.Password)
	require.NoError(t, err)
	err = utils.GenerateBlock()
	require.NoError(t, err)

	var receive utils.ArkReceive
	receiveStr, err := runArkCommand("receive")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(receiveStr), &receive))

	_, err = runArkCommand("send", "--amount", "1000", "--to", receive.Offchain, "--password", utils.Password)
	require.NoError(t, err)

	var balance utils.ArkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)
}

func TestUnilateralExit(t *testing.T) {
	_, err := runArkCommand("onboard", "--amount", "1000", "--password", utils.Password)
	require.NoError(t, err)
	err = utils.GenerateBlock()
	require.NoError(t, err)

	var balance utils.ArkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)
	require.Len(t, balance.Onchain.Locked, 0)

	_, err = runArkCommand("redeem", "--force", "--password", utils.Password)
	require.NoError(t, err)

	err = utils.GenerateBlock()
	require.NoError(t, err)

	balanceStr, err = runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.Zero(t, balance.Offchain.Total)
	require.Greater(t, len(balance.Onchain.Locked), 0)

	lockedBalance := balance.Onchain.Locked[0].Amount
	require.NotZero(t, lockedBalance)
}

func TestCollaborativeExit(t *testing.T) {
	_, err := runArkCommand("onboard", "--amount", "1000", "--password", utils.Password)
	require.NoError(t, err)
	err = utils.GenerateBlock()
	require.NoError(t, err)

	var receive utils.ArkReceive
	receiveStr, err := runArkCommand("receive")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(receiveStr), &receive))

	var balance utils.ArkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))

	balanceBefore := balance.Offchain.Total
	balanceOnchainBefore := balance.Onchain.Spendable

	_, err = runArkCommand("redeem", "--amount", "1000", "--address", receive.Onchain, "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	balanceStr, err = runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))

	require.Equal(t, balanceBefore-1000, balance.Offchain.Total)
	require.Equal(t, balanceOnchainBefore+1000, balance.Onchain.Spendable)
}

func runArkCommand(arg ...string) (string, error) {
	args := append([]string{"exec", "-t", "arkd", "ark"}, arg...)
	return utils.RunCommand("docker", args...)
}

func setupAspWallet() error {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequest("GET", "http://localhost:8080/v1/admin/wallet/seed", nil)
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
	req, err = http.NewRequest("POST", "http://localhost:8080/v1/admin/wallet/create", reqBody)
	if err != nil {
		return fmt.Errorf("failed to prepare wallet create request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	if _, err := adminHttpClient.Do(req); err != nil {
		return fmt.Errorf("failed to create wallet: %s", err)
	}

	reqBody = bytes.NewReader([]byte(fmt.Sprintf(`{"password": "%s"}`, utils.Password)))
	req, err = http.NewRequest("POST", "http://localhost:8080/v1/admin/wallet/unlock", reqBody)
	if err != nil {
		return fmt.Errorf("failed to prepare wallet unlock request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	if _, err := adminHttpClient.Do(req); err != nil {
		return fmt.Errorf("failed to unlock wallet: %s", err)
	}

	time.Sleep(time.Second)

	req, err = http.NewRequest("GET", "http://localhost:8080/v1/admin/wallet/address", nil)
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

	if _, err := utils.RunCommand("nigiri", "faucet", "--liquid", addr.Address); err != nil {
		return fmt.Errorf("failed to fund wallet: %s", err)
	}
	if _, err := utils.RunCommand("nigiri", "faucet", "--liquid", addr.Address); err != nil {
		return fmt.Errorf("failed to fund wallet: %s", err)
	}
	if _, err := utils.RunCommand("nigiri", "faucet", "--liquid", addr.Address); err != nil {
		return fmt.Errorf("failed to fund wallet: %s", err)
	}

	return nil
}
