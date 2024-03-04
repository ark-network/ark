package e2e

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
)

const (
	password = "password"
)

type arkBalance struct {
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

type arkReceive struct {
	Offchain string `json:"offchain_address"`
	Onchain  string `json:"onchain_address"`
}

func runOceanCommand(arg ...string) (string, error) {
	args := append([]string{"exec", "oceand", "ocean"}, arg...)
	return runCommand("docker", args...)
}

func runArkCommand(arg ...string) (string, error) {
	args := append([]string{"exec", "-t", "arkd", "ark"}, arg...)
	return runCommand("docker", args...)
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
		io.Copy(output, stdout)
	}()

	go func() {
		defer wg.Done()
		io.Copy(errorb, stderr)
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
