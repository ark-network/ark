package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/macaroon.v2"
)

// flags
var (
	passwordFlag = &cli.StringFlag{
		Name:     flagPassword,
		Usage:    "wallet password",
		Required: true,
	}
	mnemonicFlag = &cli.StringFlag{
		Name:  flagMnemonic,
		Usage: "mnemonic from which restore the wallet",
	}
	gapLimitFlag = &cli.Uint64Flag{
		Name:  flagGapLimit,
		Usage: "address gap limit for wallet restoration",
		Value: 100,
	}
	amountFlag = &cli.UintFlag{
		Name:     flagAmount,
		Usage:    "amount of the note in satoshis",
		Required: true,
	}
	quantityFlag = &cli.UintFlag{
		Name:  flagQuantity,
		Usage: "quantity of notes to create",
		Value: 1,
	}
)

// commands
var (
	walletCmd = &cli.Command{
		Name:  "wallet",
		Usage: "Manage the Ark Server wallet",
		Subcommands: append(
			cli.Commands{},
			walletStatusCmd,
			walletCreateOrRestoreCmd,
			walletUnlockCmd,
			walletAddressCmd,
			walletBalanceCmd,
			createNoteCmd,
		),
	}
	walletStatusCmd = &cli.Command{
		Name:   "status",
		Usage:  "Get info about the status of the wallet",
		Action: walletStatusAction,
	}
	walletCreateOrRestoreCmd = &cli.Command{
		Name:   "create",
		Usage:  "Create or restore the wallet",
		Action: walletCreateOrRestoreAction,
		Flags:  []cli.Flag{passwordFlag, mnemonicFlag, gapLimitFlag},
	}
	walletUnlockCmd = &cli.Command{
		Name:   "unlock",
		Usage:  "Unlock the wallet",
		Action: walletUnlockAction,
		Flags:  []cli.Flag{passwordFlag},
	}
	walletAddressCmd = &cli.Command{
		Name:   "address",
		Usage:  "Generate a receiving address",
		Action: walletAddressAction,
	}
	walletBalanceCmd = &cli.Command{
		Name:   "balance",
		Usage:  "Get the wallet balance",
		Action: walletBalanceAction,
	}
	createNoteCmd = &cli.Command{
		Name:   "note",
		Usage:  "Create a credit note",
		Action: createNoteAction,
		Flags:  []cli.Flag{amountFlag, quantityFlag},
	}
)

var timeout = time.Minute

func walletStatusAction(ctx *cli.Context) error {
	baseURL := ctx.String(flagURL)
	_, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/status", baseURL)
	status, err := getStatus(url, tlsCertPath)
	if err != nil {
		return err
	}

	fmt.Println(status)
	return nil
}

func walletCreateOrRestoreAction(ctx *cli.Context) error {
	baseURL := ctx.String(flagURL)
	_, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	password := ctx.String(flagPassword)
	mnemonic := ctx.String(flagMnemonic)
	gapLimit := ctx.Uint64(flagGapLimit)

	if len(mnemonic) > 0 {
		url := fmt.Sprintf("%s/v1/admin/wallet/restore", baseURL)
		body := fmt.Sprintf(
			`{"seed": "%s", "password": "%s", "gap_limit": %d}`,
			mnemonic, password, gapLimit,
		)
		if _, err := post[struct{}](url, body, "", "", tlsCertPath); err != nil {
			return err
		}

		fmt.Println("wallet restored")
		return nil
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/seed", baseURL)
	seed, err := get[string](url, "seed", "", tlsCertPath)
	if err != nil {
		return err
	}

	url = fmt.Sprintf("%s/v1/admin/wallet/create", baseURL)
	body := fmt.Sprintf(
		`{"seed": "%s", "password": "%s"}`, seed, password,
	)
	if _, err := post[struct{}](url, body, "", "", tlsCertPath); err != nil {
		return err
	}

	fmt.Println(seed)
	return nil
}

func walletUnlockAction(ctx *cli.Context) error {
	baseURL := ctx.String(flagURL)
	_, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	password := ctx.String(flagPassword)
	url := fmt.Sprintf("%s/v1/admin/wallet/unlock", baseURL)
	body := fmt.Sprintf(`{"password": "%s"}`, password)

	if _, err := post[struct{}](url, body, "", "", tlsCertPath); err != nil {
		return err
	}

	fmt.Println("wallet unlocked")
	return nil
}

func walletAddressAction(ctx *cli.Context) error {
	baseURL := ctx.String(flagURL)
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/address", baseURL)
	addr, err := get[string](url, "address", macaroon, tlsCertPath)
	if err != nil {
		return err
	}

	fmt.Println(addr)
	return nil
}

func walletBalanceAction(ctx *cli.Context) error {
	baseURL := ctx.String(flagURL)
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/wallet/balance", baseURL)
	balance, err := getBalance(url, macaroon, tlsCertPath)
	if err != nil {
		return err
	}

	fmt.Println(balance)
	return nil
}

func createNoteAction(ctx *cli.Context) error {
	baseURL := ctx.String(flagURL)
	amount := ctx.Uint(flagAmount)
	quantity := ctx.Uint(flagQuantity)
	macaroon, tlsCertPath, err := getCredentialPaths(ctx)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/admin/note", baseURL)
	body := fmt.Sprintf(`{"amount": %d, "quantity": %d}`, amount, quantity)

	notes, err := post[[]string](url, body, "notes", macaroon, tlsCertPath)
	if err != nil {
		return err
	}

	for _, note := range notes {
		fmt.Println(note)
	}

	return nil
}

func getCredentialPaths(ctx *cli.Context) (macaroon string, tlsCertPath string, err error) {
	datadir := ctx.String(flagDatadir)

	macaroonPath := filepath.Join(datadir, macaroonDir, macaroonFile)
	if _, err := os.Stat(macaroonPath); err == nil {
		macaroon, err = getMacaroon(macaroonPath)
		if err != nil {
			return "", "", fmt.Errorf("failed to read macaroon: %w", err)
		}
	}

	tlsCertPath = filepath.Join(datadir, tlsDir, tlsCertFile)
	if strings.Contains(ctx.String(flagURL), "http://") {
		tlsCertPath = ""
	}

	return macaroon, tlsCertPath, nil
}

func post[T any](url, body, key, macaroon, tlsCert string) (result T, err error) {
	tlsConfig, err := getTLSConfig(tlsCert)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Add("Content-Type", "application/json")
	if len(macaroon) > 0 {
		req.Header.Add("X-Macaroon", macaroon)
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("failed to post: %s", string(buf))
		return
	}
	if key == "" {
		return
	}
	res := make(map[string]T)
	if err = json.Unmarshal(buf, &res); err != nil {
		return
	}

	result = res[key]
	return
}

func get[T any](url, key, macaroon, tlsCert string) (result T, err error) {
	tlsConfig, err := getTLSConfig(tlsCert)
	if err != nil {
		return
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("Content-Type", "application/json")
	if len(macaroon) > 0 {
		req.Header.Add("X-Macaroon", macaroon)
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("failed to get: %s", string(buf))
		return
	}

	res := make(map[string]T)
	if err = json.Unmarshal(buf, &res); err != nil {
		return
	}

	result = res[key]
	return
}

type accountBalance struct {
	Available string `json:"available"`
	Locked    string `json:"locked"`
}

func (b accountBalance) String() string {
	return fmt.Sprintf("   available: %s\n   locked: %s", b.Available, b.Locked)
}

type balance struct {
	MainAccount       accountBalance `json:"mainAccount"`
	ConnectorsAccount accountBalance `json:"connectorsAccount"`
}

func (b balance) String() string {
	return fmt.Sprintf(
		"main account\n%s\nconnectors account\n%s",
		b.MainAccount, b.ConnectorsAccount,
	)
}

func getBalance(url, macaroon, tlsCert string) (*balance, error) {
	tlsConfig, err := getTLSConfig(tlsCert)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	if len(macaroon) > 0 {
		req.Header.Add("X-Macaroon", macaroon)
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s", buf)
		return nil, err
	}

	result := &balance{}
	if err := json.Unmarshal(buf, result); err != nil {
		return nil, err
	}
	return result, nil
}

type status struct {
	Initialized bool `json:"initialized"`
	Unlocked    bool `json:"unlocked"`
	Synced      bool `json:"synced"`
}

func (s status) String() string {
	return fmt.Sprintf(
		"initialized: %t\nunlocked: %t\nsynced: %t",
		s.Initialized, s.Unlocked, s.Synced,
	)
}

func getStatus(url, tlsCert string) (*status, error) {
	tlsConfig, err := getTLSConfig(tlsCert)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("failed to get status: %s", string(buf))
		return nil, err
	}

	result := &status{}
	if err := json.Unmarshal(buf, result); err != nil {
		return nil, err
	}
	return result, nil
}

func getMacaroon(path string) (string, error) {
	macBytes, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read macaroon %s: %s", path, err)
	}
	mac := &macaroon.Macaroon{}
	if err := mac.UnmarshalBinary(macBytes); err != nil {
		return "", fmt.Errorf("failed to parse macaroon %s: %s", path, err)
	}

	return hex.EncodeToString(macBytes), nil
}

func getTLSConfig(path string) (*tls.Config, error) {
	if len(path) <= 0 {
		return nil, nil
	}
	var buf []byte
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(buf); !ok {
		return nil, fmt.Errorf("failed to parse tls cert")
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    caCertPool,
	}, nil
}
