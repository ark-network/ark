package e2e_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ark-network/ark/common"
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

	if err := utils.SetupAspWallet(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	time.Sleep(3 * time.Second)

	_, err = utils.RunArkCommand("init", "--asp-url", "localhost:6060", "--password", utils.Password, "--network", common.LiquidRegTest.Name, "--explorer", "http://chopsticks-liquid:3000")
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
	receiveStr, err := utils.RunArkCommand("receive")
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal([]byte(receiveStr), &receive))

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = utils.RunArkCommand("claim", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	_, err = utils.RunArkCommand("send", "--amount", "1000", "--to", receive.Offchain, "--password", utils.Password)
	require.NoError(t, err)

	var balance utils.ArkBalance
	balanceStr, err := utils.RunArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)
}

func TestUnilateralExit(t *testing.T) {
	var receive utils.ArkReceive
	receiveStr, err := utils.RunArkCommand("receive")
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal([]byte(receiveStr), &receive))

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = utils.RunArkCommand("claim", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	var balance utils.ArkBalance
	balanceStr, err := utils.RunArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)

	_, err = utils.RunArkCommand("redeem", "--force", "--password", utils.Password)
	require.NoError(t, err)

	err = utils.GenerateBlock()
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	balanceStr, err = utils.RunArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.Zero(t, balance.Offchain.Total)
	require.Greater(t, len(balance.Onchain.Locked), 0)

	lockedBalance := balance.Onchain.Locked[0].Amount
	require.NotZero(t, lockedBalance)
}

func TestCollaborativeExit(t *testing.T) {
	var receive utils.ArkReceive
	receiveStr, err := utils.RunArkCommand("receive")
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal([]byte(receiveStr), &receive))

	_, err = utils.RunCommand("nigiri", "faucet", "--liquid", receive.Boarding)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = utils.RunArkCommand("claim", "--password", utils.Password)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	_, err = utils.RunArkCommand("redeem", "--amount", "10000", "--address", redeemAddr, "--password", utils.Password)
	require.NoError(t, err)
}
