package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	middleware "github.com/ark-network/ark/simulation/sdk-middleware"
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
	var clientID string
	var aspUrl string
	flag.StringVar(&clientID, "id", "", "Client ID")
	flag.StringVar(&aspUrl, "asp-url", "", "ASP URL")
	flag.Parse()

	if clientID == "" {
		log.Fatal("Client ID is required")
	}

	if aspUrl == "" {
		log.Fatal("ASP URL is required")
	}

	client := &Client{
		ID: clientID,
	}

	client.ctx, client.cancel = context.WithCancel(context.Background())

	go client.handleSignals()

	err := client.setupArkClient(aspUrl)
	if err != nil {
		log.Fatalf("Failed to set up client: %v", err)
	}

	err = client.connectToOrchestrator()
	if err != nil {
		log.Fatalf("Failed to connect to orchestrator: %v", err)
	}

	client.listenForCommands()
}

func (c *Client) setupArkClient(aspUrl string) error {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType: types.InMemoryStore,
	})
	if err != nil {
		return fmt.Errorf("failed to create store: %s", err)
	}

	originalClient, err := arksdk.NewCovenantlessClient(appDataStore)
	if err != nil {
		return fmt.Errorf("failed to setup ark client: %s", err)
	}

	inMemoryStatsCollector := middleware.NewInMemoryStatsCollector()
	loggingStatsCollector := middleware.NewLoggingStatsCollector()

	statsCollector := middleware.NewCompositeStatsCollector(
		inMemoryStatsCollector,
		loggingStatsCollector,
	)

	chain := middleware.NewChain(
		middleware.NewCPUUtilizationMiddleware(statsCollector),
		middleware.NewMemoryStatsMiddleware(statsCollector),
	)

	client := middleware.NewArkClientProxy(originalClient, chain)

	ctx := context.Background()
	if err := client.Init(ctx, arksdk.InitArgs{
		WalletType: arksdk.SingleKeyWallet,
		ClientType: arksdk.GrpcClient,
		ServerUrl:  aspUrl,
		Password:   "password",
	}); err != nil {
		return fmt.Errorf("failed to initialize wallet: %s", err)
	}

	if err := client.Unlock(ctx, "password"); err != nil {
		return fmt.Errorf("failed to unlock wallet: %s", err)
	}

	log.Infof("Client %s initialized ArkClient", c.ID)
	c.ArkClient = client
	c.StatsCollector = inMemoryStatsCollector
	return nil
}

func (c *Client) connectToOrchestrator() error {
	u := url.URL{
		Scheme:   "ws",
		Host:     "localhost:9000",
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
	case "Redeem":
		force, ok := command.Data["force"].(bool)
		if !ok {
			c.sendError("Invalid force in redeem command")
			return
		}
		amount, ok := command.Data["amount"].(float64)
		if !ok {
			c.sendError("Invalid amount in redeem command")
			return
		}
		address, ok := command.Data["address"].(string)
		if !ok {
			c.sendError("Invalid address in redeem command")
			return
		}
		computeExpiration, ok := command.Data["compute_expiration"].(bool)
		if !ok {
			c.sendError("Invalid compute_expiration in redeem command")
			return
		}
		err := c.redeem(force, amount, address, computeExpiration)
		if err != nil {
			c.sendError(fmt.Sprintf("Redeem failed: %v", err))
		}
	case "Stats":
		err := c.stats()
		if err != nil {
			c.sendError(fmt.Sprintf("Failed to get stats: %v", err))
		}
	case "Shutdown":
		c.cancel()
	default:
		log.Infof("Unknown command type: %s", command.Type)
	}
}

func (c *Client) sendError(message string) {
	msg := ClientMessage{
		Type: "Error",
		Data: message,
	}
	c.Conn.WriteJSON(msg)
}

func (c *Client) onboard(amount float64) error {
	ctx := context.Background()

	_, boardingAddress, err := c.ArkClient.Receive(ctx)
	if err != nil {
		return err
	}

	amountStr := fmt.Sprintf("%.8f", amount)

	cmdRequest := map[string]interface{}{
		"command": "nigiri",
		"args":    []string{"faucet", boardingAddress, amountStr},
	}
	err = c.sendCommandRequest(cmdRequest)
	if err != nil {
		return err
	}

	time.Sleep(5 * time.Second)

	_, err = c.ArkClient.Settle(ctx)
	if err != nil {
		return fmt.Errorf("client %s failed to onboard: %v", c.ID, err)
	}

	log.Infof("Client %s onboarded successfully with %f BTC", c.ID, amount)
	c.sendLog(fmt.Sprintf("Onboarded with %f BTC", amount))
	return nil
}

func (c *Client) sendAsync(amount float64, toClientID string) error {
	ctx := context.Background()

	recipientAddress, err := c.requestRecipientAddress(toClientID)
	if err != nil {
		return err
	}

	receivers := []arksdk.Receiver{
		arksdk.NewBitcoinReceiver(recipientAddress, uint64(amount*1e8)),
	}

	_, err = c.ArkClient.SendOffChain(ctx, false, receivers)
	if err != nil {
		return fmt.Errorf("client %s failed to send %f BTC to client %s: %v",
			c.ID, amount, toClientID, err)
	}

	log.Infof("Client %s sent %f BTC to client %s", c.ID, amount, toClientID)
	c.sendLog(fmt.Sprintf("Sent %f BTC to client %s", amount, toClientID))
	return nil
}

func (c *Client) redeem(force bool, amount float64, address string, computeExpiration bool) error {
	if force {
		if err := c.ArkClient.UnilateralRedeem(c.ctx); err != nil {
			return fmt.Errorf("client %s failed to redeem: %v", c.ID, err)
		}

		log.Infof("client %s redeemed funds", c.ID)
		c.sendLog(fmt.Sprintf("client %v redeemed funds unilaterally", c.ID))
		return nil
	}

	txID, err := c.ArkClient.CollaborativeRedeem(c.ctx, address, uint64(amount*1e8), computeExpiration)
	if err != nil {
		return fmt.Errorf("client %s failed to redeem: %v", c.ID, err)
	}

	log.Infof("client %s redeemed funds, tx: %v", c.ID, txID)
	c.sendLog(fmt.Sprintf("client %v redeemed funds colaboaratively, tx: %v", c.ID, txID))

	return nil
}

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

	log.Infof("Client %s balance: %v", c.ID, balance)
	c.sendLog(fmt.Sprintf("Balance: %v", balance))
	return nil
}

func (c *Client) stats() error {
	stats := c.StatsCollector.Stats
	log.Infof("Client %s stats: %v", c.ID, stats)
	c.sendLog(fmt.Sprintf("Stats: %v", stats))
	return nil
}

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

func (c *Client) sendLog(message string) {
	msg := ClientMessage{
		Type: "Log",
		Data: message,
	}
	c.Conn.WriteJSON(msg)
}

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

func (c *Client) handleSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	c.cancel()
}

type Command struct {
	Type string                 `json:"type"`
	Data map[string]interface{} `json:"data,omitempty"`
}

type ClientMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data,omitempty"`
}

type Client struct {
	ID             string
	Conn           *websocket.Conn
	ArkClient      arksdk.ArkClient
	ctx            context.Context
	cancel         context.CancelFunc
	Address        string
	StatsCollector *middleware.InMemoryStatsCollector
}

func printJSON(resp interface{}) error {
	jsonBytes, err := json.MarshalIndent(resp, "", "\t")
	if err != nil {
		return err
	}
	log.Infoln(string(jsonBytes))
	return nil
}
