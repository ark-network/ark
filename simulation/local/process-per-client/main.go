package main

import (
	"encoding/json"
	"flag"
	"fmt"
	utils "github.com/ark-network/ark/server/test/e2e"
	"github.com/xeipuuv/gojsonschema"
	"net/url"

	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"
)

const (
	composePath    = "../docker-compose.clark.regtest.yml"
	simulationPath = "simulation.yaml"
	clientPath     = "./build/client"
	defaultAspUrl  = "localhost:7070"
)

var (
	clients   = make(map[string]*ClientConnection)
	clientsMu sync.Mutex
	upgrader  = websocket.Upgrader{}
)

func main() {
	// Parse command-line flags
	simFile := flag.String("sim", simulationPath, "Path to simulation YAML file")
	serverAddress := flag.String("server", "", "Orchestrator server address")
	flag.Parse()

	// Load and validate the simulation YAML file
	simulation, err := loadAndValidateSimulation(*simFile)
	if err != nil {
		log.Fatalf("Error loading simulation config: %v", err)
	}

	// Determine the ASP URL, start ASP locally if no server address is provided
	aspUrl := *serverAddress
	if aspUrl == "" {
		if err := startAspLocally(*simulation); err != nil {
			log.Fatalf("Error starting ASP server: %v", err)
		}
		aspUrl = defaultAspUrl
	}

	aspUrlParsed := &url.URL{
		Scheme: "http",
		Host:   aspUrl,
	}
	// Setup the server wallet with the initial funding
	if err := utils.SetupServerWalletCovenantless(aspUrlParsed.String(), simulation.Server.InitialFunding); err != nil {
		log.Fatal(err)
	}

	// Start the orchestrator HTTP server
	go startServer()

	// Start clients
	err = startClients(aspUrl, simulation.Clients)
	if err != nil {
		log.Fatalf("Error starting clients: %v", err)
	}

	// Wait for clients to connect
	time.Sleep(2 * time.Second)

	go func() {
		for {
			if err := utils.GenerateBlock(); err != nil {
				log.Fatal(err)
			}

			time.Sleep(1 * time.Second)
		}
	}()

	// Execute the simulation
	executeSimulation(simulation)

	// Stop clients after simulation
	stopClients()
}

// startAspLocally starts ASP server locally.
func startAspLocally(simulation Simulation) error {
	log.Infof("Simulation Version: %s\n", simulation.Version)
	log.Infof("ASP Network: %s\n", simulation.Server.Network)
	log.Infof("Number of Clients: %d\n", len(simulation.Clients))
	log.Infof("Number of Rounds: %d\n", len(simulation.Rounds))

	roundLifetime := fmt.Sprintf("ARK_ROUND_INTERVAL=%d", simulation.Server.RoundInterval)
	tmpfile, err := os.CreateTemp("", "docker-env")
	if err != nil {
		return err
	}
	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write([]byte(roundLifetime)); err != nil {
		return err
	}
	if err := tmpfile.Close(); err != nil {
		return err
	}

	log.Infof("Start building ARKD docker container ...")
	if _, err := utils.RunCommand("docker", "compose", "-f", composePath, "--env-file", tmpfile.Name(), "up", "-d"); err != nil {
		return err
	}

	time.Sleep(10 * time.Second)
	log.Infoln("ASP running...")

	return nil
}

// loadAndValidateSimulation reads and validates the simulation YAML file.
func loadAndValidateSimulation(simFile string) (*Simulation, error) {
	// Read and convert the schema YAML file to JSON
	schemaBytes, err := os.ReadFile("schema.yaml")
	if err != nil {
		return nil, fmt.Errorf("error reading schema file: %v", err)
	}

	schemaJSON, err := yaml.YAMLToJSON(schemaBytes)
	if err != nil {
		return nil, fmt.Errorf("error converting schema YAML to JSON: %v", err)
	}

	// Read and convert the simulation YAML file to JSON
	simBytes, err := os.ReadFile(simFile)
	if err != nil {
		return nil, fmt.Errorf("error reading simulation file: %v", err)
	}

	simJSON, err := yaml.YAMLToJSON(simBytes)
	if err != nil {
		return nil, fmt.Errorf("error converting simulation YAML to JSON: %v", err)
	}

	// Create JSON loaders for the schema and the document
	schemaLoader := gojsonschema.NewBytesLoader(schemaJSON)
	documentLoader := gojsonschema.NewBytesLoader(simJSON)

	// Validate the simulation JSON against the schema JSON
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return nil, fmt.Errorf("error validating simulation: %v", err)
	}

	if !result.Valid() {
		// Collect error messages
		var errorMessages string
		for _, desc := range result.Errors() {
			errorMessages += fmt.Sprintf("- %s\n", desc)
		}
		return nil, fmt.Errorf("the simulation is not valid:\n%s", errorMessages)
	}

	// Unmarshal the simulation YAML into the Simulation struct
	var sim Simulation
	err = json.Unmarshal(simJSON, &sim)
	if err != nil {
		return nil, fmt.Errorf("error parsing simulation YAML: %v", err)
	}

	return &sim, nil
}

// startClients launches each client as a separate process.
func startClients(aspUrl string, clientConfigs []ClientConfig) error {
	var wg sync.WaitGroup

	for _, client := range clientConfigs {
		wg.Add(1)
		go func(client ClientConfig) {
			defer wg.Done()
			clientID := client.ID

			// Open a log file for the client
			logFileName := fmt.Sprintf("./log/client_%s.log", clientID)
			logFile, err := os.Create(logFileName)
			if err != nil {
				log.Errorf("failed to create log file for client %s: %v", clientID, err)
				return
			}

			cmd := exec.Command(clientPath, "--asp-url", aspUrl, "--id", clientID)
			cmd.Stdout = logFile
			cmd.Stderr = logFile
			err = cmd.Start()
			if err != nil {
				log.Errorf("failed to start client %s: %v", clientID, err)
				return
			}
			// Store the command process to stop it later if needed
			clientsMu.Lock()
			clients[clientID] = &ClientConnection{
				ID:     clientID,
				Conn:   nil, // Will be set when the client connects
				Cmd:    cmd,
				ConnMu: sync.Mutex{},
			}
			clientsMu.Unlock()
		}(client)
	}

	wg.Wait()
	// Give the client some time to start
	time.Sleep(200 * time.Millisecond)
	log.Infof("All clients started")
	return nil
}

// stopClients terminates all client processes.
func stopClients() {
	// Send shutdown commands to clients
	for clientID := range clients {
		if err := sendCommand(clientID, Command{
			Type: "Shutdown",
		}); err != nil {
			log.Errorf("Error sending shutdown command to client %s: %v", clientID, err)
		}
	}
}

func executeSimulation(simulation *Simulation) {
	for _, round := range simulation.Rounds {
		waitRound := false
		log.Infof("Executing Round %d at %s", round.Number, time.Now().Format("2006-01-02 15:04:05"))
		var wg sync.WaitGroup
		for clientID, actions := range round.Actions {
			wg.Add(1)
			go func(clientID string, actions []ActionMap) {
				defer wg.Done()
				for _, action := range actions {
					actionType, ok := action["type"].(string)
					if !ok {
						log.Infof("Invalid action type for client %s", clientID)
						return
					}

					if actionType == "Onboard" || actionType == "Claim" || actionType == "CollaborativeRedeem" {
						waitRound = true
					}

					// Prepare the command based on actionType
					command := Command{
						Type: actionType,
						Data: action,
					}
					// Send the command to the client
					err := sendCommand(clientID, command)
					if err != nil {
						log.Warnf("Error sending %s to client %s: %v", actionType, clientID, err)
						return
					}
				}
			}(clientID, actions)
		}
		wg.Wait()

		sleepTime := 2 * time.Second
		if waitRound {
			sleepTime = time.Duration(simulation.Server.RoundInterval)*time.Second + 2*time.Second
		}
		log.Infof("Waiting for %s before starting next round", sleepTime)
		time.Sleep(sleepTime)
		log.Infof("Round %d completed at %s", round.Number, time.Now().Format("2006-01-02 15:04:05"))
	}
}

// startServer starts the orchestrator's HTTP server.
func startServer() {
	http.HandleFunc("/ws", wsHandler)
	http.HandleFunc("/cmd", cmdHandler)
	http.HandleFunc("/log", logHandler)
	http.HandleFunc("/address", addressHandler) // Added address handler
	// Start the server
	log.Infoln("Orchestrator HTTP server running on port 9000")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Fatalf("Orchestrator server failed: %v", err)
	}
}

// wsHandler handles WebSocket connections from clients.
func wsHandler(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP connection to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Infoln("Upgrade error:", err)
		return
	}
	// Read client ID from query parameters
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		log.Infoln("Client ID not provided")
		conn.Close()
		return
	}

	clientsMu.Lock()
	clientConn, exists := clients[clientID]
	if !exists {
		// New client, add to the clients map
		clientConn = &ClientConnection{
			ID: clientID,
		}
		clients[clientID] = clientConn
	}
	clientConn.Conn = conn
	clientsMu.Unlock()

	// Listen for messages from the client
	go func() {
		defer conn.Close()
		for {
			var message ClientMessage
			err := conn.ReadJSON(&message)
			if err != nil {
				log.Infof("Error reading from client %s: %v", clientID, err)
				break
			}
			handleClientMessage(clientID, message)
		}
		// Client disconnected
		log.Infof("Client %s disconnected", clientID)
		clientsMu.Lock()
		delete(clients, clientID)
		clientsMu.Unlock()
	}()
}

// sendCommand sends a command to a client.
func sendCommand(clientID string, command Command) error {
	clientsMu.Lock()
	clientConn, exists := clients[clientID]
	clientsMu.Unlock()
	if !exists || clientConn.Conn == nil {
		return fmt.Errorf("client %s not connected", clientID)
	}

	clientConn.ConnMu.Lock()
	defer clientConn.ConnMu.Unlock()

	return clientConn.Conn.WriteJSON(command)
}

// handleClientMessage processes messages received from clients.
func handleClientMessage(clientID string, message ClientMessage) {
	// Process the message based on its type
	switch message.Type {
	case "Log":
		log.Infof("Log from client %s: %s", clientID, message.Data)
	case "Address":
		address, ok := message.Data.(string)
		if !ok {
			log.Infof("Invalid address from client %s", clientID)
			return
		}
		clientsMu.Lock()
		clientConn, exists := clients[clientID]
		if exists {
			clientConn.Address = address
		}
		clientsMu.Unlock()
	case "Error":
		log.Warnf("Error from client %s: %s", clientID, message.Data)
	default:
		log.Infof("Unknown message type from client %s: %s", clientID, message.Type)
	}
}

// addressHandler handles requests for client addresses.
func addressHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}

	clientsMu.Lock()
	clientConn, exists := clients[clientID]
	clientsMu.Unlock()
	if !exists {
		http.Error(w, fmt.Sprintf("client %s not found", clientID), http.StatusNotFound)
		return
	}
	if clientConn.Address == "" {
		http.Error(w, fmt.Sprintf("address for client %s not available", clientID), http.StatusNotFound)
		return
	}

	res := struct {
		Address string `json:"address"`
	}{
		Address: clientConn.Address,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// cmdHandler handles command execution requests from clients.
func cmdHandler(w http.ResponseWriter, r *http.Request) {
	var cmdRequest struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	err := json.NewDecoder(r.Body).Decode(&cmdRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Infof("Executing command: %s %v", cmdRequest.Command, cmdRequest.Args)
	// Execute the command
	output, err := exec.Command(cmdRequest.Command, cmdRequest.Args...).CombinedOutput()
	if err != nil {
		log.Infof("Command execution failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Infof("Command output: %s", output)
	w.WriteHeader(http.StatusOK)
}

// logHandler handles log messages from clients.
func logHandler(w http.ResponseWriter, r *http.Request) {
	var logEntry map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&logEntry)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Infof("Log from client: %v", logEntry)
	w.WriteHeader(http.StatusOK)
}

// Command represents a command sent to a client.
type Command struct {
	Type string                 `json:"type"`
	Data map[string]interface{} `json:"data,omitempty"`
}

// ClientMessage represents a message received from a client.
type ClientMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data,omitempty"`
}

// ClientConfig holds configuration for a client.
type ClientConfig struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ActionMap represents an action in the simulation rounds.
type ActionMap map[string]interface{}

// Round represents a simulation round.
type Round struct {
	Number  int                    `json:"number"`
	Actions map[string][]ActionMap `json:"actions"`
}

// Simulation represents the entire simulation configuration.
type Simulation struct {
	Version string `json:"version"`
	Server  struct {
		Network        string  `json:"network"`
		InitialFunding float64 `json:"initial_funding"`
		RoundInterval  int     `json:"round_interval"`
	} `yaml:"server"`
	Clients []ClientConfig `json:"clients"`
	Rounds  []Round        `json:"rounds"`
}

// ClientConnection holds information about a connected client.
type ClientConnection struct {
	ID      string
	Conn    *websocket.Conn
	Address string
	Cmd     *exec.Cmd
	ConnMu  sync.Mutex
}
