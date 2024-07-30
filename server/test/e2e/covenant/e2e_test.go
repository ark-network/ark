package e2e_test

import (
	"encoding/json"
	"fmt"
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
	_, err := utils.RunCommand("docker-compose", "-f", composePath, "up", "-d", "--build")
	if err != nil {
		fmt.Printf("error starting docker-compose: %s", err)
		os.Exit(1)
	}

	_, err = runOceanCommand("config", "init", "--no-tls")
	if err != nil {
		fmt.Printf("error initializing ocean config: %s", err)
		os.Exit(1)
	}

	_, err = runOceanCommand("wallet", "create", "--password", utils.Password)
	if err != nil {
		fmt.Printf("error creating ocean wallet: %s", err)
		os.Exit(1)
	}

	_, err = runOceanCommand("wallet", "unlock", "--password", utils.Password)
	if err != nil {
		fmt.Printf("error unlocking ocean wallet: %s", err)
		os.Exit(1)
	}

	_, err = runOceanCommand("account", "create", "--label", "ark", "--unconf")
	if err != nil {
		fmt.Printf("error creating ocean account: %s", err)
		os.Exit(1)
	}

	addrJSON, err := runOceanCommand("account", "derive", "--account-name", "ark")
	if err != nil {
		fmt.Printf("error deriving ocean account: %s", err)
		os.Exit(1)
	}

	var addr struct {
		Addresses []string `json:"addresses"`
	}

	if err := json.Unmarshal([]byte(addrJSON), &addr); err != nil {
		fmt.Printf("error unmarshalling ocean account: %s (%s)", err, addrJSON)
		os.Exit(1)
	}

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", addr.Addresses[0])
	if err != nil {
		fmt.Printf("error funding ocean account: %s", err)
		os.Exit(1)
	}

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", addr.Addresses[0])
	if err != nil {
		fmt.Printf("error funding ocean account: %s", err)
		os.Exit(1)
	}

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", addr.Addresses[0])
	if err != nil {
		fmt.Printf("error funding ocean account: %s", err)
		os.Exit(1)
	}

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", addr.Addresses[0])
	if err != nil {
		fmt.Printf("error funding ocean account: %s", err)
		os.Exit(1)
	}

	time.Sleep(3 * time.Second)

	_, err = runArkCommand("init", "--ark-url", "localhost:6000", "--password", utils.Password, "--network", common.LiquidRegTest.Name, "--explorer", "http://chopsticks-liquid:3000")
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

	_, err = utils.RunCommand("docker-compose", "-f", composePath, "down")
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

func runOceanCommand(arg ...string) (string, error) {
	args := append([]string{"exec", "oceand", "ocean"}, arg...)
	return utils.RunCommand("docker", args...)
}

func runArkCommand(arg ...string) (string, error) {
	args := append([]string{"exec", "-t", "arkd", "ark"}, arg...)
	return utils.RunCommand("docker", args...)
}
