package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	utils "github.com/ark-network/ark/server/test/e2e"
	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/shirou/gopsutil/net"
)

const (
	composePath = "../../../../docker-compose.clark.regtest.yml"
)

func TestMain(m *testing.M) {
	_, err := utils.RunCommand("docker", "compose", "-f", composePath, "up", "-d", "--build")
	if err != nil {
		fmt.Printf("error starting docker-compose: %s", err)
		os.Exit(1)
	}

	time.Sleep(10 * time.Second)

	if err := utils.GenerateBlock(); err != nil {
		fmt.Printf("error generating block: %s", err)
		os.Exit(1)
	}

	if err := setupAspWallet(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	time.Sleep(3 * time.Second)

	if err := playwright.Install(); err != nil {
		fmt.Printf("error installing playwright: %v", err)
		os.Exit(1)
	}

	_, err = runClarkCommand("init", "--server-url", "localhost:7070", "--password", utils.Password, "--network", "regtest", "--explorer", "http://chopsticks:3000")
	if err != nil {
		fmt.Printf("error initializing ark config: %s", err)
		os.Exit(1)
	}

	code := m.Run()

	_, err = utils.RunCommand("docker", "compose", "-f", composePath, "down", "-v")
	if err != nil {
		fmt.Printf("error stopping docker-compose: %s", err)
		os.Exit(1)
	}

	if err := killProcessByPort(8000); err != nil {
		fmt.Printf("failed to kill process running on 8000, err: %v", err)
		os.Exit(1)
	}

	fmt.Println("killed web server running on 8000")
	os.Exit(code)
}

func TestWasm(t *testing.T) {
	pw, err := playwright.Run()
	require.NoError(t, err)
	defer pw.Stop()

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	require.NoError(t, err)
	defer browser.Close()

	alicePage, err := browser.NewPage()
	require.NoError(t, err)

	bobPage, err := browser.NewPage()
	require.NoError(t, err)

	cleanup, err := setupPages(t, []*playwright.Page{&alicePage, &bobPage})
	require.NoError(t, err)
	defer cleanup()

	time.Sleep(10 * time.Second)

	t.Log("Alice is setting up her ark wallet...")
	require.NoError(t, initWallet(alicePage))

	t.Log("Bob is setting up his ark wallet...")
	require.NoError(t, initWallet(bobPage))

	time.Sleep(2 * time.Second)

	t.Log("Getting Bob's receive address...")
	bobAddr, err := getReceiveAddress(bobPage)
	require.NoError(t, err)
	t.Logf("Bob's Offchain Address: %v\n", bobAddr.OffchainAddr)

	t.Log("Alice is acquiring onchain funds...")
	aliceAddr, err := getReceiveAddress(alicePage)
	require.NoError(t, err)
	t.Logf("Alice's Boarding Address: %v\n", aliceAddr.BoardingAddr)

	_, err = runCommand("nigiri", "faucet", aliceAddr.BoardingAddr)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)
	err = generateBlock()
	require.NoError(t, err)
	time.Sleep(2 * time.Second)

	txID, err := settle(alicePage)
	require.NoError(t, err)
	t.Logf("Alice onboard txID: %v", txID)

	aliceBalance, err := getBalance(alicePage)
	require.NoError(t, err)
	t.Logf("Alice onchain balance: %v", aliceBalance.OnchainSpendable)
	t.Logf("Alice offchain balance: %v", aliceBalance.OffchainBalance)

	bobBalance, err := getBalance(bobPage)
	require.NoError(t, err)
	t.Logf("Bob onchain balance: %v", bobBalance.OnchainSpendable)
	t.Logf("Bob offchain balance: %v", bobBalance.OffchainBalance)

	amount := 1000
	t.Logf("Alice is sending %d sats to Bob offchain...", amount)
	require.NoError(t, sendOffChain(alicePage, bobAddr.OffchainAddr, amount))

	t.Log("Transaction completed out of round")

	t.Logf("Bob settling the received funds...")
	txID, err = settle(bobPage)
	require.NoError(t, err)
	t.Logf("Bob settled the received funds in round %v", txID)

	err = generateBlock()
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	aliceBalance, err = getBalance(alicePage)
	require.NoError(t, err)
	t.Logf("Alice onchain balance: %v", aliceBalance.OnchainSpendable)
	t.Logf("Alice offchain balance: %v", aliceBalance.OffchainBalance)

	bobBalance, err = getBalance(bobPage)
	require.NoError(t, err)
	t.Logf("Bob onchain balance: %v", bobBalance.OnchainSpendable)
	t.Logf("Bob offchain balance: %v", bobBalance.OffchainBalance)
	assert.Equal(t, amount, bobBalance.OffchainBalance)
}

type Address struct {
	BoardingAddr string
	OffchainAddr string
}

type Balance struct {
	OnchainSpendable int
	OnchainLocked    int
	OffchainBalance  int
}

func setupPages(t *testing.T, pages []*playwright.Page) (func(), error) {
	var cleanupFuncs []func()

	for _, page := range pages {
		p := *page
		_, err := p.Goto("http://localhost:8000")
		require.NoError(t, err)

		p.OnConsole(func(msg playwright.ConsoleMessage) {
			t.Logf("console text: %v", msg.Text())
		})

		responseCleanup := make(chan struct{})
		cleanupFuncs = append(cleanupFuncs, func() { close(responseCleanup) })

		p.OnResponse(func(response playwright.Response) {
			go func() {
				select {
				case <-responseCleanup:
					return
				default:
					resp, err := response.Text()
					if err != nil {
						// Only log if it's not a "target closed" error
						if !strings.Contains(err.Error(), "Target page, context or browser has been closed") {
							t.Logf("could not get response text: %v", err)
						}
						return
					}
					t.Logf("response from %v: %v", response.URL(), resp)
				}
			}()
		})

		p.OnRequestFailed(func(request playwright.Request) {
			t.Logf("request to %v failed", request.URL())
		})
	}

	return func() {
		for _, cleanup := range cleanupFuncs {
			cleanup()
		}
	}, nil
}

func initWallet(page playwright.Page) error {
	_, err := page.Evaluate(`async () => { 
        try {
            const chain = "bitcoin";
            const walletType = "singlekey";
            const clientType = "rest";
            const privateKey = "";
            const password = "pass";
            const explorerUrl = "";
            const serverUrl = "http://localhost:7070";    
            return await init(walletType, clientType, serverUrl, privateKey, password, chain, explorerUrl);
        } catch (err) {
            console.error("Init error:", err);
            throw err;
        } 
    }`)
	return err
}

func getReceiveAddress(page playwright.Page) (*Address, error) {
	result, err := page.Evaluate(`async () => { 
        try {
            return await receive();
        } catch (err) {
            console.error("Receive error:", err);
            throw err;
        }
    }`)
	if err != nil {
		return nil, err
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("result is not a map")
	}

	boardingAddr, ok := resultMap["boardingAddr"].(string)
	if !ok {
		return nil, fmt.Errorf("boardingAddr not found or not a string")
	}

	offchainAddr, ok := resultMap["offchainAddr"].(string)
	if !ok {
		return nil, fmt.Errorf("offchainAddr not found or not a string")
	}

	return &Address{
		BoardingAddr: boardingAddr,
		OffchainAddr: offchainAddr,
	}, nil
}

func getBalance(page playwright.Page) (*Balance, error) {
	result, err := page.Evaluate(`async () => { 
        try {
            return await balance(false);
        } catch (err) {
            console.error("Error:", err);
            throw err;
        }
    }`)
	if err != nil {
		return nil, err
	}

	balanceMap, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("result is not a map")
	}

	onchainBalance, ok := balanceMap["onchainBalance"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("onchainBalance not found or not a map")
	}

	offchainBalance, ok := balanceMap["offchainBalance"].(int)
	if !ok {
		return nil, fmt.Errorf("offchainBalance not found or not a int")
	}

	spendable, ok := onchainBalance["spendable"].(int)
	if !ok {
		return nil, fmt.Errorf("spendable not found or not a int")
	}

	locked, ok := onchainBalance["locked"].(int)
	if !ok {
		return nil, fmt.Errorf("locked not found or not a int")
	}

	return &Balance{
		OnchainSpendable: spendable,
		OnchainLocked:    locked,
		OffchainBalance:  offchainBalance,
	}, nil
}

func settle(page playwright.Page) (string, error) {
	result, err := page.Evaluate(`async () => { 
        try {
            await unlock("pass");
            return await settle((e) => console.log(JSON.parse(e)));
        } catch (err) {
            console.error("Error:", err);
            throw err;
        }
    }`)
	if err != nil {
		return "", err
	}
	return fmt.Sprint(result), nil
}

func sendOffChain(page playwright.Page, addr string, amount int) error {
	_, err := page.Evaluate(fmt.Sprintf(`async () => { 
        try {
            return await sendOffChain(false, [{To:"%s", Amount:%d}]);
        } catch (err) {
            console.error("Error:", err);
            throw err;
        }
    }`, addr, amount))
	return err
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

func setupAspWallet() error {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequest("GET", "http://localhost:7070/v1/admin/wallet/seed", nil)
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
	req, err = http.NewRequest("POST", "http://localhost:7070/v1/admin/wallet/create", reqBody)
	if err != nil {
		return fmt.Errorf("failed to prepare wallet create request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	if _, err := adminHttpClient.Do(req); err != nil {
		return fmt.Errorf("failed to create wallet: %s", err)
	}

	reqBody = bytes.NewReader([]byte(fmt.Sprintf(`{"password": "%s"}`, utils.Password)))
	req, err = http.NewRequest("POST", "http://localhost:7070/v1/admin/wallet/unlock", reqBody)
	if err != nil {
		return fmt.Errorf("failed to prepare wallet unlock request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	if _, err := adminHttpClient.Do(req); err != nil {
		return fmt.Errorf("failed to unlock wallet: %s", err)
	}

	var status struct {
		Initialized bool `json:"initialized"`
		Unlocked    bool `json:"unlocked"`
		Synced      bool `json:"synced"`
	}
	for {
		time.Sleep(time.Second)

		req, err := http.NewRequest("GET", "http://localhost:7070/v1/admin/wallet/status", nil)
		if err != nil {
			return fmt.Errorf("failed to prepare status request: %s", err)
		}
		resp, err := adminHttpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to get status: %s", err)
		}
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			return fmt.Errorf("failed to parse status response: %s", err)
		}
		if status.Initialized && status.Unlocked && status.Synced {
			break
		}
	}

	var addr struct {
		Address string `json:"address"`
	}
	for addr.Address == "" {
		time.Sleep(time.Second)

		req, err = http.NewRequest("GET", "http://localhost:7070/v1/admin/wallet/address", nil)
		if err != nil {
			return fmt.Errorf("failed to prepare new address request: %s", err)
		}
		req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")

		resp, err := adminHttpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to get new address: %s", err)
		}

		if err := json.NewDecoder(resp.Body).Decode(&addr); err != nil {
			return fmt.Errorf("failed to parse response: %s", err)
		}
	}

	const numberOfFaucet = 15 // must cover the liquidity needed for all tests

	for i := 0; i < numberOfFaucet; i++ {
		_, err = utils.RunCommand("nigiri", "faucet", addr.Address)
		if err != nil {
			return fmt.Errorf("failed to fund wallet: %s", err)
		}
	}

	time.Sleep(5 * time.Second)
	return nil
}

func runClarkCommand(arg ...string) (string, error) {
	args := append([]string{"exec", "-t", "clarkd", "ark"}, arg...)
	return utils.RunCommand("docker", args...)
}

func findProcessByPort(port uint32) (int32, error) {
	connections, err := net.Connections("tcp")
	if err != nil {
		return 0, fmt.Errorf("failed to get network connections: %v", err)
	}

	for _, conn := range connections {
		if conn.Laddr.Port == uint32(port) {
			return conn.Pid, nil
		}
	}

	return 0, fmt.Errorf("no process found using port %v", port)
}

func killProcessByPID(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process with PID %v: %v", pid, err)
	}

	if err := process.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("failed to kill process with PID %v: %v", pid, err)
	}

	fmt.Printf("Successfully killed process with PID %v.\n", pid)
	return nil
}

func killProcessByPort(port int) error {
	pid, err := findProcessByPort(uint32(port))
	if err != nil {
		return err
	}

	return killProcessByPID(int(pid))
}
