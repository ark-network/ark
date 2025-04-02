package e2e

import (
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

const (
	Password = "password"
	// #nosec G101
	NostrTestingSecretKey = "07959d1d2bc6507403449c556585d463a9ca4374eb0ec07b3929088ce6c34a7e"
)

type ArkBalance struct {
	Offchain struct {
		Total int `json:"total"`
	} `json:"offchain_balance"`
	Onchain struct {
		Spendable int `json:"spendable_amount"`
		Locked    []struct {
			Amount      int    `json:"amount"`
			SpendableAt string `json:"spendable_at"`
		} `json:"locked_amount"`
	} `json:"onchain_balance"`
}

type ArkReceive struct {
	Offchain string `json:"offchain_address"`
	Boarding string `json:"boarding_address"`
}

func GenerateBlock() error {
	if _, err := RunCommand("nigiri", "rpc", "--liquid", "generatetoaddress", "1", "el1qqwk722tghgkgmh3r2ph4d2apwj0dy9xnzlenzklx8jg3z299fpaw56trre9gpk6wmw0u4qycajqeva3t7lzp7wnacvwxha59r"); err != nil {
		return err
	}
	if _, err := RunCommand("nigiri", "rpc", "generatetoaddress", "1", "bcrt1qe8eelqalnch946nzhefd5ajhgl2afjw5aegc59"); err != nil {
		return err
	}
	return nil
}

func GetBlockHeight(isLiquid bool) (uint32, error) {
	var out string
	var err error
	if isLiquid {
		out, err = RunCommand("nigiri", "rpc", "--liquid", "getblockcount")
	} else {
		out, err = RunCommand("nigiri", "rpc", "getblockcount")
	}
	if err != nil {
		return 0, err
	}
	height, err := strconv.ParseUint(strings.TrimSpace(out), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(height), nil
}

func RunDockerExec(container string, arg ...string) (string, error) {
	args := append([]string{"exec", "-t", container}, arg...)
	return RunCommand("docker", args...)
}

func RunCommand(name string, arg ...string) (string, error) {
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
