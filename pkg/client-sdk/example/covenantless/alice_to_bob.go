package main

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	inmemorystore "github.com/ark-network/ark/pkg/client-sdk/store/inmemory"
	sqlitestore "github.com/ark-network/ark/pkg/client-sdk/store/sqlite"
	log "github.com/sirupsen/logrus"
)

var (
	aspUrl     = "localhost:7070"
	clientType = arksdk.GrpcClient
	password   = "password"
	walletType = arksdk.SingleKeyWallet
)

func main() {
	ctx := context.Background()

	log.Info("alice is setting up her ark wallet...")

	aliceArkClient, err := setupArkClient()
	if err != nil {
		log.Fatal(err)
	}

	if err := aliceArkClient.Unlock(ctx, password); err != nil {
		log.Fatal(err)
	}
	//nolint:all
	defer aliceArkClient.Lock(ctx, password)

	log.Info("alice is acquiring onchain funds...")
	_, boardingAddress, err := aliceArkClient.Receive(ctx)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := runCommand("nigiri", "faucet", boardingAddress); err != nil {
		log.Fatal(err)
	}

	time.Sleep(5 * time.Second)

	onboardAmount := uint64(1_0000_0000) // 1 BTC
	log.Infof("alice is onboarding with %d sats offchain...", onboardAmount)

	aliceBalance, err := aliceArkClient.Balance(ctx, false)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("alice onchain balance: %d", aliceBalance.OnchainBalance.SpendableAmount)
	log.Infof("alice offchain balance: %d", aliceBalance.OffchainBalance.Total)

	log.Infof("alice claiming onboarding funds...")
	txid, err := aliceArkClient.Claim(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("alice claimed onboarding funds in round %s", txid)

	fmt.Println("")
	log.Info("bob is setting up his ark wallet...")
	bobArkClient, err := setupArkClient()
	if err != nil {
		log.Fatal(err)
	}

	if err := bobArkClient.Unlock(ctx, password); err != nil {
		log.Fatal(err)
	}
	//nolint:all
	defer bobArkClient.Lock(ctx, password)

	bobOffchainAddr, _, err := bobArkClient.Receive(ctx)
	if err != nil {
		log.Fatal(err)
	}

	bobBalance, err := bobArkClient.Balance(ctx, false)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("bob onchain balance: %d", bobBalance.OnchainBalance.SpendableAmount)
	log.Infof("bob offchain balance: %d", bobBalance.OffchainBalance.Total)

	amount := uint64(1000)
	receivers := []arksdk.Receiver{
		arksdk.NewBitcoinReceiver(bobOffchainAddr, amount),
	}

	fmt.Println("")
	log.Infof("alice is sending %d sats to bob offchain...", amount)

	if _, err = aliceArkClient.SendAsync(ctx, false, receivers); err != nil {
		log.Fatal(err)
	}

	log.Info("payment completed out of round")

	if err := generateBlock(); err != nil {
		log.Fatal(err)
	}

	time.Sleep(5 * time.Second)

	aliceBalance, err = aliceArkClient.Balance(ctx, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("")
	log.Infof("alice onchain balance: %d", aliceBalance.OnchainBalance.SpendableAmount)
	log.Infof("alice offchain balance: %d", aliceBalance.OffchainBalance.Total)

	bobBalance, err = bobArkClient.Balance(ctx, false)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("bob onchain balance: %d", bobBalance.OnchainBalance.SpendableAmount)
	log.Infof("bob offchain balance: %d", bobBalance.OffchainBalance.Total)

	fmt.Println("")
	log.Info("bob is claiming the incoming payment...")
	roundTxid, err := bobArkClient.Claim(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("bob claimed the incoming payment in round %s", roundTxid)
}

func setupArkClient() (arksdk.ArkClient, error) {
	storeSvc, err := inmemorystore.NewConfigStore()
	if err != nil {
		return nil, fmt.Errorf("failed to setup store: %s", err)
	}
	dbDir := fmt.Sprintf("%s/%s", common.AppDataDir("ark-example", false), "sqlite")
	appDataStoreMigrationPath := "file://../../pkg/client-sdk/store/sqlite/migrations"
	appDataStore, err := sqlitestore.NewAppDataRepository(dbDir, appDataStoreMigrationPath)
	client, err := arksdk.NewCovenantlessClient(storeSvc, appDataStore)
	if err != nil {
		return nil, fmt.Errorf("failed to setup ark client: %s", err)
	}

	if err := client.Init(context.Background(), arksdk.InitArgs{
		WalletType: walletType,
		ClientType: clientType,
		AspUrl:     aspUrl,
		Password:   password,
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize wallet: %s", err)
	}

	return client, nil
}

func runCommand(name string, arg ...string) (string, error) {
	errb := new(strings.Builder)
	cmd := newCommand(name, arg...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}
	output := new(strings.Builder)
	errorb := new(strings.Builder)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(output, stdout); err != nil {
			fmt.Fprintf(errb, "error reading stdout: %s", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(errorb, stderr); err != nil {
			fmt.Fprintf(errb, "error reading stderr: %s", err)
		}
	}()

	wg.Wait()
	if err := cmd.Wait(); err != nil {
		if errMsg := errorb.String(); len(errMsg) > 0 {
			return "", fmt.Errorf("%s", errMsg)
		}

		if outMsg := output.String(); len(outMsg) > 0 {
			return "", fmt.Errorf("%s", outMsg)
		}

		return "", err
	}

	if errMsg := errb.String(); len(errMsg) > 0 {
		return "", fmt.Errorf("%s", errMsg)
	}

	return strings.Trim(output.String(), "\n"), nil
}

func newCommand(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	return cmd
}

func generateBlock() error {
	if _, err := runCommand("nigiri", "rpc", "generatetoaddress", "1", "bcrt1qgqsguk6wax7ynvav4zys5x290xftk49h5agg0l"); err != nil {
		return err
	}

	time.Sleep(6 * time.Second)
	return nil
}
