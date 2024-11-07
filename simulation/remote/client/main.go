package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	log "github.com/sirupsen/logrus"
)

const (
	clientPort = "9000"
)

var (
	orchestratorUrl string
)

func main() {
	clientID := os.Getenv("CLIENT_ID")
	aspUrl := os.Getenv("ASP_URL")
	orchUrl := os.Getenv("ORCHESTRATOR_URL")
	explorerUrl := os.Getenv("EXPLORER_URL")
	signetAspUrl := os.Getenv("SIMNET_ASP_URL")
	if clientID == "" {
		log.Fatal("CLIENT_ID environment variable is required")
	}
	if aspUrl == "" && signetAspUrl == "" {
		log.Fatal("ASP_URL environment variable is required")
	}
	if orchUrl == "" {
		log.Fatal("ORCHESTRATOR_URL environment variable is required")
	}
	orchestratorUrl = orchUrl
	if explorerUrl == "" {
		log.Fatal("EXPLORER_URL environment variable is required")
	}
	if signetAspUrl != "" {
		aspUrl = signetAspUrl
		signetExplorerUrl := os.Getenv("SIGNET_EXPLORER_URL")
		if signetExplorerUrl == "" {
			log.Fatal("SIGNET_EXPLORER_URL environment variable is required")
		}
		explorerUrl = signetExplorerUrl
	}

	log.Infof("Env vars: CLIENT_ID=%s, ASP_URL=%s, ORCHESTRATOR_URL=%s, EXPLORER_URL=%s", clientID, aspUrl, orchestratorUrl, explorerUrl)

	client := &Client{
		ID: clientID,
	}

	// Initialize context for cancellation
	client.ctx, client.cancel = context.WithCancel(context.Background())

	// Set up ArkClient
	if err := client.setupArkClient(explorerUrl, aspUrl); err != nil {
		log.Fatalf("Failed to set up client: %v", err)
	}

	// Start HTTP server
	go client.startServer()

	time.Sleep(20 * time.Second)

	// Send address to orchestrator
	if err := client.sendAddress(); err != nil {
		log.Fatalf("Failed to send address to orchestrator: %v", err)
	}

	// Wait for shutdown signal
	client.handleSignals()
}

type Client struct {
	ID        string
	ArkClient arksdk.ArkClient
	ctx       context.Context
	cancel    context.CancelFunc
	Address   string
}

func (c *Client) setupArkClient(explorerUrl, aspUrl string) error {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType: types.InMemoryStore,
	})
	if err != nil {
		return fmt.Errorf("failed to create store: %s", err)
	}

	client, err := arksdk.NewCovenantlessClient(appDataStore)
	if err != nil {
		return fmt.Errorf("failed to setup ark client: %s", err)
	}

	ctx := context.Background()
	if err := client.Init(ctx, arksdk.InitArgs{
		WalletType:  arksdk.SingleKeyWallet,
		ClientType:  arksdk.RestClient,
		AspUrl:      aspUrl,
		Password:    "password",
		ExplorerURL: explorerUrl,
	}); err != nil {
		return fmt.Errorf("failed to initialize wallet: %s", err)
	}

	if err := client.Unlock(ctx, "password"); err != nil {
		return fmt.Errorf("failed to unlock wallet: %s", err)
	}

	log.Infof("Client %s initialized ArkClient", c.ID)
	c.ArkClient = client
	return nil
}

func (c *Client) startServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/onboard", c.onboardHandler)
	mux.HandleFunc("/sendAsync", c.sendAsyncHandler)
	mux.HandleFunc("/claim", c.claimHandler)
	mux.HandleFunc("/balance", c.balanceHandler)

	server := &http.Server{
		Addr:    ":" + clientPort,
		Handler: mux,
	}

	go func() {
		<-c.ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	log.Infof("Client %s starting HTTP server on port %s", c.ID, clientPort)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Client server failed: %v", err)
	}
}

func (c *Client) sendAddress() error {
	ctx := context.Background()
	offchainAddress, _, err := c.ArkClient.Receive(ctx)
	if err != nil {
		return fmt.Errorf("failed to get address: %v", err)
	}
	c.Address = offchainAddress

	payload := struct {
		ClientID string `json:"client_id"`
		Address  string `json:"address"`
	}{
		ClientID: c.ID,
		Address:  offchainAddress,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(fmt.Sprintf("http://%s/address", orchestratorUrl),
		"application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var body map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return fmt.Errorf("failed to register address: status=%d, body=%v", resp.StatusCode, body)
	}

	log.Infof("Client %s registered address %s with orchestrator", c.ID, offchainAddress)
	return nil
}

func (c *Client) onboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Amount float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := c.onboard(orchestratorUrl, req.Amount); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (c *Client) sendAsyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Amount    float64 `json:"amount"`
		ToAddress string  `json:"to_address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	receivers := []arksdk.Receiver{
		arksdk.NewBitcoinReceiver(req.ToAddress, uint64(req.Amount*1e8)),
	}

	_, err := c.ArkClient.SendAsync(ctx, false, receivers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	logMsg := fmt.Sprintf("Client %s sent async %f BTC to %s", c.ID, req.Amount, req.ToAddress)
	log.Infoln(logMsg)
	if err := c.sendLogToOrchestrator(logMsg, "Info"); err != nil {
		log.Errorf("Failed to send log to orchestrator: %v", err)
	}

	w.WriteHeader(http.StatusOK)
}

func (c *Client) claimHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := c.claim(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (c *Client) balanceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := context.Background()
	balance, err := c.ArkClient.Balance(ctx, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(balance)
}

func (c *Client) onboard(orchestratorUrl string, amount float64) error {
	ctx := context.Background()

	_, boardingAddress, err := c.ArkClient.Receive(ctx)
	if err != nil {
		return err
	}

	amountStr := fmt.Sprintf("%.8f", amount)

	payload := struct {
		Address string `json:"address"`
		Amount  string `json:"amount"`
	}{
		Address: boardingAddress,
		Amount:  amountStr,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(fmt.Sprintf("http://%s/faucet", orchestratorUrl),
		"application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var body map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return fmt.Errorf("failed to faucet address: status=%d, body=%v", resp.StatusCode, body)
	}

	// Wait for the funds to be confirmed (simulate delay)
	time.Sleep(5 * time.Second)

	_, err = c.ArkClient.Settle(ctx)
	if err != nil {
		return fmt.Errorf("client %s failed to settle onboard: %v", c.ID, err)
	}

	logMsg := fmt.Sprintf("Client %s onboarded successfully with %f BTC", c.ID, amount)
	log.Infoln(logMsg)
	if err := c.sendLogToOrchestrator(logMsg, "Info"); err != nil {
		log.Errorf("Failed to send log to orchestrator: %v", err)
	}

	return nil
}

func (c *Client) claim() error {
	ctx := context.Background()

	txID, err := c.ArkClient.Settle(ctx)
	if err != nil {
		return fmt.Errorf("client %s failed to claim funds: %v", c.ID, err)
	}

	logMsg := fmt.Sprintf("Client %s claimed funds, txID: %v", c.ID, txID)
	log.Infoln(logMsg)
	if err := c.sendLogToOrchestrator(logMsg, "Info"); err != nil {
		log.Errorf("Failed to send log to orchestrator: %v", err)
	}
	return nil
}

func (c *Client) handleSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Info("Shutting down client...")
	c.cancel()
}

func (c *Client) sendLogToOrchestrator(message, logType string) error {
	payload := struct {
		ClientID string `json:"client_id"`
		Type     string `json:"type"`
		Message  string `json:"message"`
	}{
		ClientID: c.ID,
		Type:     logType,
		Message:  message,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(fmt.Sprintf("http://%s/log", orchestratorUrl),
		"application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var body map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return fmt.Errorf("failed to send log to orchestrator: status=%d, body=%v", resp.StatusCode, body)
	}

	return nil
}
