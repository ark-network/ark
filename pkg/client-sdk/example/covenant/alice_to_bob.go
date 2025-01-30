package main

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	log "github.com/sirupsen/logrus"
)

var (
	serverUrl  = "localhost:6060"
	clientType = arksdk.GrpcClient
	password   = "password"
	walletType = arksdk.SingleKeyWallet
)

func main() {
	ctx := context.Background()

	log.Info("alice is setting up her ark wallet...")

	aliceArkClient, err := setupArkClient("alice")
	if err != nil {
		log.Fatal(err)
	}

	if err := aliceArkClient.Unlock(ctx, password); err != nil {
		log.Fatal(err)
	}
	//nolint:all
	defer aliceArkClient.Lock(ctx, password)

	log.Info("alice is acquiring onchain funds...")
	_, aliceBoardingAddr, err := aliceArkClient.Receive(ctx)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := runCommand("nigiri", "faucet", "--liquid", aliceBoardingAddr); err != nil {
		log.Fatal(err)
	}

	time.Sleep(5 * time.Second)

	onboardAmount := uint64(1_0000_0000) // 1 BTC
	log.Infof("alice is onboarding with %d sats offchain...", onboardAmount)

	log.Infof("alice settled the onboard funds...")
	txid, err := aliceArkClient.Settle(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("onboarding completed in round tx: %s", txid)

	aliceBalance, err := aliceArkClient.Balance(ctx, false)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("alice onchain balance: %d", aliceBalance.OnchainBalance.SpendableAmount)
	log.Infof("alice offchain balance: %d", aliceBalance.OffchainBalance.Total)

	fmt.Println("")
	log.Info("bob is setting up his ark wallet...")
	bobArkClient, err := setupArkClient("bob")
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
		arksdk.NewLiquidReceiver(bobOffchainAddr, amount),
	}

	fmt.Println("")
	log.Infof("alice is sending %d sats to bob offchain...", amount)

	txid, err = aliceArkClient.SendOffChain(ctx, false, receivers, false)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("transaction completed in round: %s", txid)

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
}

func setupArkClient(wallet string) (arksdk.ArkClient, error) {
	dbDir := common.AppDataDir(path.Join("ark-example", wallet), false)
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType:  types.FileStore,
		AppDataStoreType: types.KVStore,
		BaseDir:          dbDir,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to setup app data store: %s", err)
	}

	client, err := arksdk.NewCovenantClient(appDataStore)
	if err != nil {
		return nil, fmt.Errorf("failed to setup ark client: %s", err)
	}

	if err := client.Init(context.Background(), arksdk.InitArgs{
		WalletType: walletType,
		ClientType: clientType,
		ServerUrl:  serverUrl,
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
			return "", fmt.Errorf("failed cmd wait: %v", errMsg)
		}

		if outMsg := output.String(); len(outMsg) > 0 {
			return "", fmt.Errorf("failed reading output: %v", outMsg)
		}

		return "", err
	}

	if errMsg := errb.String(); len(errMsg) > 0 {
		return "", fmt.Errorf("run cmd failed: %v", errMsg)
	}

	return strings.Trim(output.String(), "\n"), nil
}

func newCommand(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	return cmd
}

func generateBlock() error {
	if _, err := runCommand("nigiri", "rpc", "--liquid", "generatetoaddress", "1", "el1qqwk722tghgkgmh3r2ph4d2apwj0dy9xnzlenzklx8jg3z299fpaw56trre9gpk6wmw0u4qycajqeva3t7lzp7wnacvwxha59r"); err != nil {
		return err
	}

	time.Sleep(6 * time.Second)
	return nil
}
