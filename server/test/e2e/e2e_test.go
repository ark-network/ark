package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const composePath = "../../../docker-compose.regtest.yml"

func TestMain(m *testing.M) {
	_, err := runCommand("docker-compose", "-f", composePath, "up", "-d", "--build")
	if err != nil {
		fmt.Printf("error starting docker-compose: %s", err)
		os.Exit(1)
	}

	_, err = runOceanCommand("config", "init", "--no-tls")
	if err != nil {
		fmt.Printf("error initializing ocean config: %s", err)
		os.Exit(1)
	}

	_, err = runOceanCommand("wallet", "create", "--password", password)
	if err != nil {
		fmt.Printf("error creating ocean wallet: %s", err)
		os.Exit(1)
	}

	_, err = runOceanCommand("wallet", "unlock", "--password", password)
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

	_, err = runCommand("nigiri", "faucet", "--liquid", addr.Addresses[0])
	if err != nil {
		fmt.Printf("error funding ocean account: %s", err)
		os.Exit(1)
	}

	time.Sleep(2 * time.Second)

	_, err = runArkCommand("init", "--ark-url", "localhost:6000", "--password", password, "--network", "regtest", "--explorer", "http://chopsticks-liquid:3000")
	if err != nil {
		fmt.Printf("error initializing ark config: %s", err)
		os.Exit(1)
	}

	var receive arkReceive
	receiveStr, err := runArkCommand("receive")
	if err != nil {
		fmt.Printf("error getting ark receive addresses: %s", err)
		os.Exit(1)
	}

	if err := json.Unmarshal([]byte(receiveStr), &receive); err != nil {
		fmt.Printf("error unmarshalling ark receive addresses: %s", err)
		os.Exit(1)
	}

	_, err = runCommand("nigiri", "faucet", "--liquid", receive.Onchain)
	if err != nil {
		fmt.Printf("error funding ark account: %s", err)
		os.Exit(1)
	}

	time.Sleep(5 * time.Second)

	code := m.Run()

	_, err = runCommand("docker-compose", "-f", composePath, "down")
	if err != nil {
		fmt.Printf("error stopping docker-compose: %s", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func TestOnboard(t *testing.T) {
	var balance arkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	balanceBefore := balance.Offchain.Total

	_, err = runArkCommand("onboard", "--amount", "1000", "--password", password)
	require.NoError(t, err)
	err = generateBlock()
	require.NoError(t, err)

	balanceStr, err = runArkCommand("balance")
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.Equal(t, balanceBefore+1000, balance.Offchain.Total)
}

func TestSendOffchain(t *testing.T) {
	_, err := runArkCommand("onboard", "--amount", "1000", "--password", password)
	require.NoError(t, err)
	err = generateBlock()
	require.NoError(t, err)

	var receive arkReceive
	receiveStr, err := runArkCommand("receive")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(receiveStr), &receive))

	_, err = runArkCommand("send", "--amount", "1000", "--to", receive.Offchain, "--password", password)
	require.NoError(t, err)

	var balance arkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)
}

func TestUnilateralExit(t *testing.T) {
	_, err := runArkCommand("onboard", "--amount", "1000", "--password", password)
	require.NoError(t, err)
	err = generateBlock()
	require.NoError(t, err)

	var balance arkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.NotZero(t, balance.Offchain.Total)
	require.Len(t, balance.Onchain.Locked, 0)

	_, err = runArkCommand("redeem", "--force", "--password", password)
	require.NoError(t, err)

	err = generateBlock()
	require.NoError(t, err)

	balanceStr, err = runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))
	require.Zero(t, balance.Offchain.Total)
	require.Len(t, balance.Onchain.Locked, 1)

	lockedBalance := balance.Onchain.Locked[0].Amount
	require.NotZero(t, lockedBalance)
}

func TestCollaborativeExit(t *testing.T) {
	_, err := runArkCommand("onboard", "--amount", "1000", "--password", password)
	require.NoError(t, err)
	err = generateBlock()
	require.NoError(t, err)

	var receive arkReceive
	receiveStr, err := runArkCommand("receive")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(receiveStr), &receive))

	var balance arkBalance
	balanceStr, err := runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))

	balanceBefore := balance.Offchain.Total
	balanceOnchainBefore := balance.Onchain.Spendable

	_, err = runArkCommand("redeem", "--amount", "1000", "--address", receive.Onchain, "--password", password)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	balanceStr, err = runArkCommand("balance")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(balanceStr), &balance))

	require.Equal(t, balanceBefore-1000, balance.Offchain.Total)
	require.Equal(t, balanceOnchainBefore+1000, balance.Onchain.Spendable)
}
