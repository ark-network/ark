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
	serverUrl  = "localhost:7070"
	clientType = arksdk.GrpcClient
	password   = "password"
	walletType = arksdk.SingleKeyWallet
)

func main() {
	var (
		ctx = context.Background()
		err error

		aliceArkClient arksdk.ArkClient
		bobArkClient   arksdk.ArkClient
	)
	defer func() {
		if aliceArkClient != nil {
			if err := bobArkClient.Stop(); err != nil {
				log.Error(err)
			}
		}

		if bobArkClient != nil {
			if err := aliceArkClient.Stop(); err != nil {
				log.Error(err)
			}
		}
	}()

	log.Info("alice is setting up her ark wallet...")

	aliceArkClient, err = setupArkClient("alice")
	if err != nil {
		log.Fatal(err)
	}

	logTxEvents("alice", aliceArkClient)

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

	log.Infof("alice is settling the onboard funds...")
	txid, err := aliceArkClient.Settle(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("alice settled the onboard funds in round %s", txid)

	fmt.Println("")
	log.Info("bob is setting up his ark wallet...")
	bobArkClient, err = setupArkClient("bob")
	if err != nil {
		log.Fatal(err)
	}

	logTxEvents("bob", bobArkClient)

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

	if _, err = aliceArkClient.SendOffChain(ctx, false, receivers, true); err != nil {
		log.Fatal(err)
	}

	log.Info("transaction completed out of round")

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
	log.Info("bob is settling the received funds...")
	roundTxid, err := bobArkClient.Settle(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("bob settled the received funds in round %s", roundTxid)

	time.Sleep(500 * time.Second)
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

	client, err := arksdk.NewCovenantlessClient(appDataStore)
	if err != nil {
		return nil, fmt.Errorf("failed to setup ark client: %s", err)
	}

	if err := client.Init(context.Background(), arksdk.InitArgs{
		WalletType:          walletType,
		ClientType:          clientType,
		ServerUrl:           serverUrl,
		Password:            password,
		WithTransactionFeed: true,
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

func logTxEvents(wallet string, client arksdk.ArkClient) {
	txsChan := client.GetTransactionEventChannel()
	go func() {
		for txEvent := range txsChan {
			msg := fmt.Sprintf("[EVENT]%s: tx event: %s, %d", wallet, txEvent.Event, txEvent.Tx.Amount)
			if txEvent.Tx.IsBoarding() {
				msg += fmt.Sprintf(", boarding tx: %s", txEvent.Tx.BoardingTxid)
			}
			log.Infoln(msg)
		}
	}()
	log.Infof("%s tx event listener started", wallet)
}
