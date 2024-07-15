package main

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	arksdk "github.com/ark-network/ark-sdk"
	"github.com/ark-network/ark-sdk/store/inmemory"
	log "github.com/sirupsen/logrus"
)

func main() {
	var (
		//grpcAspUrl = "localhost:6000"
		restAspUrl = "http://localhost:6000"
		//grpcProtocol = arksdk.Grpc
		restProtocol = arksdk.Rest
		ctx          = context.Background()

		aspUrl   = restAspUrl
		protocol = restProtocol
	)

	aliceConfigStore, err := inmemorystore.New(aspUrl, protocol)
	if err != nil {
		log.Fatal(err)
	}

	aliceWalletStore := inmemorystore.NewWalletStore()
	aliceWallet, err := arksdk.NewSingleKeyWallet(ctx, aliceWalletStore)
	if err != nil {
		log.Fatal(err)
	}

	aliceArkClient, err := arksdk.New(
		ctx,
		aliceWallet,
		aliceConfigStore,
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := aliceArkClient.Connect(ctx); err != nil {
		log.Fatal(err)
	}

	_, aliceOnchainAddr, err := aliceArkClient.Receive(ctx)
	if err != nil {
		log.Fatal(err)
	}

	_, err = runCommand("nigiri", "faucet", "--liquid", aliceOnchainAddr)
	if err != nil {
		log.Fatal(err)
	}

	if err := generateBlock(); err != nil {
		log.Fatal(err)
	}

	txID, err := aliceArkClient.Onboard(ctx, 20000)
	if err != nil {
		log.Fatal(err)
	}

	if err := generateBlock(); err != nil {
		log.Fatal(err)
	}

	time.Sleep(5 * time.Second)

	log.Infof("Alice onboarded with txID: %s", txID)

	aliceBalance, err := aliceArkClient.Balance(ctx, false)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Alice onchain balance: %d", aliceBalance.OnchainBalance.SpendableAmount)
	log.Infof("Alice offchain balance: %d", aliceBalance.OffchainBalance.Total)

	bobConfigStore, err := inmemorystore.New(aspUrl, protocol)
	if err != nil {
		log.Fatal(err)
	}

	bobWalletStore := inmemorystore.NewWalletStore()
	if _, err := bobWalletStore.CreatePrivateKey(); err != nil {
		log.Fatal(err)
	}

	bobWallet, err := arksdk.NewSingleKeyWallet(ctx, bobWalletStore)
	if err != nil {
		log.Fatal(err)
	}

	bobArkClient, err := arksdk.New(
		ctx, bobWallet, bobConfigStore,
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := bobArkClient.Connect(ctx); err != nil {
		log.Fatal(err)
	}

	bobOffchainAddr, _, err := bobArkClient.Receive(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Bob offchain address: %s", bobOffchainAddr)

	txID, err = aliceArkClient.SendOffChain(
		ctx,
		false,
		[]arksdk.Receiver{
			{
				To:     bobOffchainAddr,
				Amount: 1000,
			},
		})
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Alice sent 10000 to Bob offchain with txID: %s", txID)

	if err := generateBlock(); err != nil {
		log.Fatal(err)
	}

	time.Sleep(6 * time.Second)

	aliceBalance, err = aliceArkClient.Balance(ctx, false)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Alice onchain balance: %d", aliceBalance.OnchainBalance.SpendableAmount)
	log.Infof("Alice offchain balance: %d", aliceBalance.OffchainBalance.Total)

	bobBalance, err := bobArkClient.Balance(ctx, false)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Bob onchain balance: %d", bobBalance.OnchainBalance.SpendableAmount)
	log.Infof("Bob offchain balance: %d", bobBalance.OffchainBalance.Total)
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
			return "", fmt.Errorf(errMsg)
		}

		if outMsg := output.String(); len(outMsg) > 0 {
			return "", fmt.Errorf(outMsg)
		}

		return "", err
	}

	if errMsg := errb.String(); len(errMsg) > 0 {
		return "", fmt.Errorf(errMsg)
	}

	return strings.Trim(output.String(), "\n"), nil
}

func newCommand(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	return cmd
}

func runArkCommand(arg ...string) (string, error) {
	args := append([]string{"exec", "-t", "arkd", "ark"}, arg...)
	return runCommand("docker", args...)
}

func generateBlock() error {
	if _, err := runCommand("nigiri", "rpc", "--liquid", "generatetoaddress", "1", "el1qqwk722tghgkgmh3r2ph4d2apwj0dy9xnzlenzklx8jg3z299fpaw56trre9gpk6wmw0u4qycajqeva3t7lzp7wnacvwxha59r"); err != nil {
		return err
	}

	time.Sleep(6 * time.Second)
	return nil
}
