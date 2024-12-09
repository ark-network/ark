package main

import (
	"encoding/json"
	"flag"
	"fmt"
	utils "github.com/ark-network/ark/server/test/e2e"
	"github.com/xeipuuv/gojsonschema"
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
	schemaPath     = "./config/schema.yaml"
	simulationPath = "./config/simulation.yaml"
	clientPath     = "./build/client"
	aspUrl         = "localhost:7070"
)

var (
	clients   = make(map[string]*ClientConnection)
	clientsMu sync.Mutex
	upgrader  = websocket.Upgrader{}
)

func main() {
	simFile := flag.String("sim", simulationPath, "Path to simulation YAML file")
	flag.Parse()

	simulation, err := loadAndValidateSimulation(*simFile)
	if err != nil {
		log.Fatalf("Error loading simulation config: %v", err)
	}

	go startServer()

	err = startClients(simulation.Clients)
	if err != nil {
		log.Fatalf("Error starting clients: %v", err)
	}

	time.Sleep(2 * time.Second)

	go func() {
		for {
			if err := utils.GenerateBlock(); err != nil {
				log.Fatal(err)
			}

			time.Sleep(1 * time.Second)
		}
	}()

	executeSimulation(simulation)

	stopClients()
}

func loadAndValidateSimulation(simFile string) (*Simulation, error) {
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("error reading schema file: %v", err)
	}

	schemaJSON, err := yaml.YAMLToJSON(schemaBytes)
	if err != nil {
		return nil, fmt.Errorf("error converting schema YAML to JSON: %v", err)
	}

	simBytes, err := os.ReadFile(fmt.Sprintf("./config/%s", simFile))
	if err != nil {
		return nil, fmt.Errorf("error reading simulation file: %v", err)
	}

	simJSON, err := yaml.YAMLToJSON(simBytes)
	if err != nil {
		return nil, fmt.Errorf("error converting simulation YAML to JSON: %v", err)
	}

	schemaLoader := gojsonschema.NewBytesLoader(schemaJSON)
	documentLoader := gojsonschema.NewBytesLoader(simJSON)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return nil, fmt.Errorf("error validating simulation: %v", err)
	}

	if !result.Valid() {
		var errorMessages string
		for _, desc := range result.Errors() {
			errorMessages += fmt.Sprintf("- %s\n", desc)
		}
		return nil, fmt.Errorf("the simulation is not valid:\n%s", errorMessages)
	}

	var sim Simulation
	err = json.Unmarshal(simJSON, &sim)
	if err != nil {
		return nil, fmt.Errorf("error parsing simulation YAML: %v", err)
	}

	return &sim, nil
}

func startClients(clientConfigs []ClientConfig) error {
	var wg sync.WaitGroup

	for _, client := range clientConfigs {
		wg.Add(1)
		go func(client ClientConfig) {
			defer wg.Done()
			clientID := client.ID

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
			clientsMu.Lock()
			clients[clientID] = &ClientConnection{
				ID:     clientID,
				Conn:   nil,
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
		roundStart := time.Now()
		log.Infof("Executing Round %d at %s", round.Number, roundStart.Format("2006-01-02 15:04:05"))
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

					command := Command{
						Type: actionType,
						Data: action,
					}

					err := sendCommand(clientID, command)
					if err != nil {
						log.Warnf("Error sending %s to client %s: %v", actionType, clientID, err)
						return
					}
				}
			}(clientID, actions)
		}
		wg.Wait()

		sleepTime := 5 * time.Second
		log.Infof("Waiting for %s before starting next round", sleepTime)
		time.Sleep(sleepTime)
		log.Infof("Round %d completed in %s", round.Number, time.Since(roundStart))
	}
}

func startServer() {
	http.HandleFunc("/ws", wsHandler)
	http.HandleFunc("/cmd", cmdHandler)
	http.HandleFunc("/log", logHandler)
	http.HandleFunc("/address", addressHandler)

	log.Infoln("Orchestrator HTTP server running on port 9000")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Fatalf("Orchestrator server failed: %v", err)
	}
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Infoln("Upgrade error:", err)
		return
	}
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		log.Infoln("Client ID not provided")
		conn.Close()
		return
	}

	clientsMu.Lock()
	clientConn, exists := clients[clientID]
	if !exists {
		clientConn = &ClientConnection{
			ID: clientID,
		}
		clients[clientID] = clientConn
	}
	clientConn.Conn = conn
	clientsMu.Unlock()

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
		log.Infof("Client %s disconnected", clientID)
		clientsMu.Lock()
		delete(clients, clientID)
		clientsMu.Unlock()
	}()
}

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

func handleClientMessage(clientID string, message ClientMessage) {
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
	case "Stats":
		log.Infof("Stats from client %s: %s", clientID, message.Data)
	case "Error":
		log.Warnf("Error from client %s: %s", clientID, message.Data)
	default:
		log.Infof("Unknown message type from client %s: %s", clientID, message.Type)
	}
}

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
	output, err := exec.Command(cmdRequest.Command, cmdRequest.Args...).CombinedOutput()
	if err != nil {
		log.Infof("Command execution failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Infof("Command output: %s", output)
	w.WriteHeader(http.StatusOK)
}

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

type Command struct {
	Type string                 `json:"type"`
	Data map[string]interface{} `json:"data,omitempty"`
}

type ClientMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data,omitempty"`
}

type ClientConfig struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type ActionMap map[string]interface{}

type Round struct {
	Number  int                    `json:"number"`
	Actions map[string][]ActionMap `json:"actions"`
}

type Simulation struct {
	Version string         `json:"version"`
	Clients []ClientConfig `json:"clients"`
	Rounds  []Round        `json:"rounds"`
}

type ClientConnection struct {
	ID      string
	Conn    *websocket.Conn
	Address string
	Cmd     *exec.Cmd
	ConnMu  sync.Mutex
}
