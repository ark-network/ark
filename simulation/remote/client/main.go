package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	clientID := os.Getenv("CLIENT_ID")
	aspUrl := os.Getenv("ASP_URL")
	orchestratorUrl := os.Getenv("ORCHESTRATOR_URL")
	if clientID == "" {
		log.Fatal("CLIENT_ID environment variable is required")
	}
	if aspUrl == "" {
		log.Fatal("ASP_URL environment variable is required")
	}
	if orchestratorUrl == "" {
		log.Fatal("ORCHESTRATOR_URL environment variable is required")
	}

	client := &Client{
		ID: clientID,
	}

	// Initialize context for cancellation
	client.ctx, client.cancel = context.WithCancel(context.Background())

	// Handle OS signals for graceful shutdown
	go client.handleSignals()

	// Set up ArkClient
	err := client.setupArkClient(aspUrl)
	if err != nil {
		log.Fatalf("Failed to set up client: %v", err)
	}

	// Connect to orchestrator
	err = client.connectToOrchestrator(orchestratorUrl)
	if err != nil {
		log.Fatalf("Failed to connect to orchestrator: %v", err)
	}

	// Listen for commands from orchestrator
	client.listenForCommands()
}

// setupArkClient initializes the ArkClient for the client.
func (c *Client) setupArkClient(aspUrl string) error {
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
		WalletType: arksdk.SingleKeyWallet,
		ClientType: arksdk.GrpcClient,
		AspUrl:     aspUrl,
		Password:   "password",
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

// connectToOrchestrator establishes a WebSocket connection to the orchestrator.
func (c *Client) connectToOrchestrator(orchestratorUrl string) error {
	u := url.URL{
		Scheme:   "ws",
		Host:     orchestratorUrl,
		Path:     "/ws",
		RawQuery: fmt.Sprintf("id=%s", c.ID),
	}
	var err error
	c.Conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect to orchestrator: %v", err)
	}
	log.Infof("Connected to orchestrator")

	// Send the client's address to the orchestrator
	err = c.sendAddress()
	if err != nil {
		return fmt.Errorf("failed to send address: %v", err)
	}

	return nil
}

// sendAddress sends the client's address to the orchestrator.
func (c *Client) sendAddress() error {
	ctx := context.Background()
	offchainAddress, _, err := c.ArkClient.Receive(ctx)
	if err != nil {
		return fmt.Errorf("failed to get address: %v", err)
	}
	c.Address = offchainAddress // Store the address in the client struct

	msg := ClientMessage{
		Type: "Address",
		Data: offchainAddress,
	}
	err = c.Conn.WriteJSON(msg)
	if err != nil {
		return fmt.Errorf("failed to send address to orchestrator: %v", err)
	}
	log.Infof("Sent address to orchestrator: %s", offchainAddress)
	return nil
}

// listenForCommands listens for commands from the orchestrator.
func (c *Client) listenForCommands() {
	defer c.Conn.Close()
	for {
		select {
		case <-c.ctx.Done():
			log.Infof("Client %s shutting down", c.ID)
			return
		default:
			var command Command
			err := c.Conn.ReadJSON(&command)
			if err != nil {
				log.Infof("Error reading command: %v", err)
				return
			}
			// Handle the command
			c.handleCommand(command)
		}
	}
}

// handleCommand processes a command received from the orchestrator.
func (c *Client) handleCommand(command Command) {
	switch command.Type {
	case "Onboard":
		amount, ok := command.Data["amount"].(float64)
		if !ok {
			c.sendError("Invalid amount in Onboard command")
			return
		}
		err := c.onboard(amount)
		if err != nil {
			c.sendError(fmt.Sprintf("Onboard failed: %v", err))
		}
	case "SendAsync":
		amount, ok := command.Data["amount"].(float64)
		if !ok {
			c.sendError("Invalid amount in SendAsync command")
			return
		}
		toClientID, ok := command.Data["to"].(string)
		if !ok {
			c.sendError("Invalid recipient in SendAsync command")
			return
		}
		err := c.sendAsync(amount, toClientID)
		if err != nil {
			c.sendError(fmt.Sprintf("SendAsync failed: %v", err))
		}
	case "Claim":
		err := c.claim()
		if err != nil {
			c.sendError(fmt.Sprintf("Claim failed: %v", err))
		}
	case "Balance":
		err := c.balance()
		if err != nil {
			c.sendError(fmt.Sprintf("Failed to get balance: %v", err))
		}

	case "Shutdown":
		c.cancel()
	// Add other command types as needed
	default:
		log.Infof("Unknown command type: %s", command.Type)
	}
}

// sendError sends an error message back to the orchestrator.
func (c *Client) sendError(message string) {
	msg := ClientMessage{
		Type: "Error",
		Data: message,
	}
	c.Conn.WriteJSON(msg)
}

// onboard performs the onboarding process for the client.
func (c *Client) onboard(amount float64) error {
	ctx := context.Background()

	_, boardingAddress, err := c.ArkClient.Receive(ctx)
	if err != nil {
		return err
	}

	amountStr := fmt.Sprintf("%.8f", amount)

	// Send command execution request to orchestrator
	cmdRequest := map[string]interface{}{
		"command": "nigiri",
		"args":    []string{"faucet", boardingAddress, amountStr},
	}
	err = c.sendCommandRequest(cmdRequest)
	if err != nil {
		return err
	}

	// Wait for the funds to be confirmed (simulate delay)
	time.Sleep(5 * time.Second)

	_, err = c.ArkClient.Settle(ctx)
	if err != nil {
		return fmt.Errorf("client %s failed to onboard: %v", c.ID, err)
	}

	log.Infof("Client %s onboarded successfully with %f BTC", c.ID, amount)
	c.sendLog(fmt.Sprintf("Onboarded with %f BTC", amount))
	return nil
}

// sendAsync sends funds asynchronously to another client.
func (c *Client) sendAsync(amount float64, toClientID string) error {
	ctx := context.Background()

	// Request recipient address from orchestrator
	recipientAddress, err := c.requestRecipientAddress(toClientID)
	if err != nil {
		return err
	}

	receivers := []arksdk.Receiver{
		arksdk.NewBitcoinReceiver(recipientAddress, uint64(amount*1e8)),
	}

	_, err = c.ArkClient.SendAsync(ctx, false, receivers)
	if err != nil {
		return fmt.Errorf("client %s failed to send %f BTC to client %s: %v",
			c.ID, amount, toClientID, err)
	}

	log.Infof("Client %s sent %f BTC to client %s", c.ID, amount, toClientID)
	c.sendLog(fmt.Sprintf("Sent %f BTC to client %s", amount, toClientID))
	return nil
}

// claim performs the claim action for the client.
func (c *Client) claim() error {
	ctx := context.Background()

	txID, err := c.ArkClient.Settle(ctx)
	if err != nil {
		return fmt.Errorf("client %s failed to claim funds: %v", c.ID, err)
	}

	log.Infof("Client %s claimed funds, txID: %v", c.ID, txID)
	c.sendLog(fmt.Sprintf("Claimed funds, txID: %v", txID))
	return nil
}

func (c *Client) balance() error {
	ctx := context.Background()

	balance, err := c.ArkClient.Balance(ctx, false)
	if err != nil {
		return fmt.Errorf("client %s failed to get balance: %v", c.ID, err)
	}

	return printJSON(balance)
}

// sendCommandRequest sends a command execution request to the orchestrator.
func (c *Client) sendCommandRequest(cmdRequest map[string]interface{}) error {
	jsonData, _ := json.Marshal(cmdRequest)
	resp, err := http.Post("http://localhost:9000/cmd", "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("command execution failed with status %d", resp.StatusCode)
	}
	return nil
}

// sendLog sends a log message to the orchestrator.
func (c *Client) sendLog(message string) {
	msg := ClientMessage{
		Type: "Log",
		Data: message,
	}
	c.Conn.WriteJSON(msg)
}

// requestRecipientAddress requests the recipient's address from the orchestrator.
func (c *Client) requestRecipientAddress(toClientID string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("http://localhost:9000/address?client_id=%s", toClientID))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get address for client %s", toClientID)
	}
	var res struct {
		Address string `json:"address"`
	}
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return "", err
	}
	return res.Address, nil
}

// handleSignals handles OS signals for graceful shutdown.
func (c *Client) handleSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	c.cancel()
}

// Command represents a command received from the orchestrator.
type Command struct {
	Type string                 `json:"type"`
	Data map[string]interface{} `json:"data,omitempty"`
}

// ClientMessage represents a message sent to the orchestrator.
type ClientMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data,omitempty"`
}

// Client struct represents a client instance.
type Client struct {
	ID        string
	Conn      *websocket.Conn
	ArkClient arksdk.ArkClient
	ctx       context.Context
	cancel    context.CancelFunc
	Address   string // Added Address field
}

func printJSON(resp interface{}) error {
	jsonBytes, err := json.MarshalIndent(resp, "", "\t")
	if err != nil {
		return err
	}
	log.Infoln(string(jsonBytes))
	return nil
}
