package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/sync/errgroup"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	utils "github.com/ark-network/ark/server/test/e2e"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecsTypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"
)

const (
	composePath    = "../../../docker-compose.clark.regtest.yml"
	schemaPath     = "../../schema.yaml"
	simulationPath = "../../simulation.yaml"
	defaultAspUrl  = "localhost:7070"
)

var (
	clients   = make(map[string]*ClientConnection)
	clientsMu sync.Mutex // Protects the clients map
	upgrader  = websocket.Upgrader{}
)

func main() {
	// Parse command-line flags
	simFile := flag.String("sim", simulationPath, "Path to simulation YAML file")
	serverAddress := flag.String("server", "", "Orchestrator server address")
	flag.Parse()

	subnetIDsEnv := os.Getenv("SUBNET_IDS")
	securityGroupIDsEnv := os.Getenv("SECURITY_GROUP_IDS")

	if subnetIDsEnv == "" {
		log.Fatalf("SUBNET_IDS environment variable is not set")
	}
	if securityGroupIDsEnv == "" {
		log.Fatalf("SECURITY_GROUP_IDS environment variable is not set")
	}

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
	err = startClients(subnetIDsEnv, securityGroupIDsEnv, simulation.Clients)
	if err != nil {
		log.Fatalf("Error starting clients: %v", err)
	}

	// Wait for clients to connect and send their addresses
	clientIDs := make([]string, len(simulation.Clients))
	for i, client := range simulation.Clients {
		clientIDs[i] = client.ID
	}
	waitForClientsToSendAddresses(clientIDs)

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
	if _, err := utils.RunCommand("docker-compose", "-f", composePath, "--env-file", tmpfile.Name(), "up", "-d"); err != nil {
		return err
	}

	time.Sleep(10 * time.Second)
	log.Infoln("ASP running...")

	return nil
}

// loadAndValidateSimulation reads and validates the simulation YAML file.
func loadAndValidateSimulation(simFile string) (*Simulation, error) {
	// Read and convert the schema YAML file to JSON
	schemaBytes, err := os.ReadFile(schemaPath)
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

// startClients launches each client as an AWS Fargate task.
func startClients(subnetIDsEnv, securityGroupIDsEnv string, clientConfigs []ClientConfig) error {
	awsRegion := "eu-central-1"
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(awsRegion),
	)
	if err != nil {
		return fmt.Errorf("unable to load AWS SDK config: %v", err)
	}

	ecsClient := ecs.NewFromConfig(cfg)

	// Split the IDs into slices
	subnetIDs := strings.Split(subnetIDsEnv, ",")
	securityGroupIDs := strings.Split(securityGroupIDsEnv, ",")

	clusterName := "OrchestratorCluster"
	taskDefinition := "ClientTaskDefinition"

	// Log task definition details
	describeTaskDefInput := &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: aws.String(taskDefinition),
	}

	taskDefDetails, err := ecsClient.DescribeTaskDefinition(context.TODO(), describeTaskDefInput)
	if err != nil {
		log.Warnf("Failed to get task definition details: %v", err)
	} else {
		log.Infof("Task Definition details: %+v", taskDefDetails.TaskDefinition)
	}

	var (
		tasksMu sync.Mutex
		tasks   []struct {
			ClientID string
			TaskArn  string
		}
	)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Function to wait for task to be running
	waitForTaskRunning := func(taskArn string, clientID string) error {
		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("timeout waiting for task to start")
			default:
				describeTasksInput := &ecs.DescribeTasksInput{
					Cluster: aws.String(clusterName),
					Tasks:   []string{taskArn},
				}

				result, err := ecsClient.DescribeTasks(context.TODO(), describeTasksInput)
				if err != nil {
					return fmt.Errorf("failed to describe task: %v", err)
				}

				if len(result.Tasks) > 0 {
					task := result.Tasks[0]
					status := aws.ToString(task.LastStatus)

					switch status {
					case "RUNNING":
						return nil
					case "STOPPED":
						// Get detailed error information
						var errorDetail string
						if task.StoppedReason != nil {
							errorDetail = *task.StoppedReason
						}

						// Check container status for more details
						for _, container := range task.Containers {
							if container.Reason != nil {
								errorDetail += fmt.Sprintf(" Container error: %s", *container.Reason)
							}
						}

						return fmt.Errorf("task stopped: %s", errorDetail)
					case "PENDING", "PROVISIONING":
						log.Infof("Client %s task status: %s", clientID, status)
					default:
						log.Infof("Client %s unexpected status: %s", clientID, status)
					}
				}

				time.Sleep(5 * time.Second)
			}
		}
	}

	// Use errgroup to manage goroutines and errors
	g := new(errgroup.Group)

	// Start all tasks concurrently
	for _, client := range clientConfigs {
		client := client // Capture range variable
		g.Go(func() error {
			clientID := client.ID

			// Prepare the overrides for the container
			containerOverrides := ecsTypes.ContainerOverride{
				Name: aws.String("ClientContainer"),
				Environment: []ecsTypes.KeyValuePair{
					{
						Name:  aws.String("CLIENT_ID"),
						Value: aws.String(clientID),
					},
				},
			}

			// Run the task
			runTaskInput := &ecs.RunTaskInput{
				Cluster:        aws.String(clusterName),
				LaunchType:     ecsTypes.LaunchTypeFargate,
				TaskDefinition: aws.String(taskDefinition),
				NetworkConfiguration: &ecsTypes.NetworkConfiguration{
					AwsvpcConfiguration: &ecsTypes.AwsVpcConfiguration{
						Subnets:        subnetIDs,
						SecurityGroups: securityGroupIDs,
						AssignPublicIp: ecsTypes.AssignPublicIpEnabled,
					},
				},
				Overrides: &ecsTypes.TaskOverride{
					ContainerOverrides: []ecsTypes.ContainerOverride{containerOverrides},
				},
			}

			result, err := ecsClient.RunTask(context.TODO(), runTaskInput)
			if err != nil {
				return fmt.Errorf("failed to start client %s: %v", clientID, err)
			}

			if len(result.Tasks) == 0 {
				return fmt.Errorf("no tasks created for client %s", clientID)
			}

			taskArn := *result.Tasks[0].TaskArn
			log.Infof("Started client %s with task ARN: %s", clientID, taskArn)

			// Store task information
			tasksMu.Lock()
			tasks = append(tasks, struct {
				ClientID string
				TaskArn  string
			}{
				ClientID: clientID,
				TaskArn:  taskArn,
			})
			tasksMu.Unlock()

			// Wait for task to be running
			if err := waitForTaskRunning(taskArn, clientID); err != nil {
				return fmt.Errorf("client %s failed to start: %v", clientID, err)
			}

			// Initialize client connection without WebSocket connection yet
			clientsMu.Lock()
			clients[clientID] = &ClientConnection{
				ID:      clientID,
				Conn:    nil,
				ConnMu:  sync.Mutex{},
				Address: "",
				TaskArn: taskArn,
			}
			clientsMu.Unlock()

			log.Infof("Client %s successfully started and running", clientID)
			return nil
		})
	}

	// Wait for all tasks to be started
	if err := g.Wait(); err != nil {
		log.Errorf("Error starting clients: %v", err)
		// If any error occurred during task startup, stop any started tasks
		stopClients()
		return err
	}

	log.Infof("All clients started successfully")

	// Monitor task health periodically
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tasksMu.Lock()
				currentTasks := make([]struct {
					ClientID string
					TaskArn  string
				}, len(tasks))
				copy(currentTasks, tasks)
				tasksMu.Unlock()

				for _, task := range currentTasks {
					describeTasksInput := &ecs.DescribeTasksInput{
						Cluster: aws.String(clusterName),
						Tasks:   []string{task.TaskArn},
					}

					result, err := ecsClient.DescribeTasks(context.TODO(), describeTasksInput)
					if err != nil {
						log.Warnf("Failed to describe task for client %s: %v", task.ClientID, err)
						continue
					}

					if len(result.Tasks) > 0 {
						status := aws.ToString(result.Tasks[0].LastStatus)
						if status == "STOPPED" {
							log.Warnf("Client %s task stopped unexpectedly", task.ClientID)
						}
					}
				}
			}
		}
	}()

	return nil
}

// getLocalPrivateIP retrieves the private IP address of the orchestrator.
func getLocalPrivateIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ip.To4() != nil {
			// Return the first IPv4 non-loopback address
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no private IP address found")
}

// waitForClientsToSendAddresses waits until all clients have sent their addresses.
func waitForClientsToSendAddresses(clientIDs []string) {
	log.Infof("Waiting for clients to send addresses...")
	for {
		allReceived := true
		clientsMu.Lock()
		for _, clientID := range clientIDs {
			clientConn, exists := clients[clientID]
			if !exists || clientConn.Address == "" {
				allReceived = false
				break
			}
		}
		clientsMu.Unlock()
		if allReceived {
			log.Infof("All clients have sent their addresses")
			return
		}
		time.Sleep(1 * time.Second)
	}
}

// stopClients terminates all client tasks.
func stopClients() {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Errorf("Unable to load AWS SDK config: %v", err)
		return
	}

	ecsClient := ecs.NewFromConfig(cfg)

	// Stop each client task
	clientsMu.Lock()
	for clientID, clientConn := range clients {
		if clientConn.TaskArn != "" {
			_, err := ecsClient.StopTask(context.TODO(), &ecs.StopTaskInput{
				Cluster: aws.String("OrchestratorCluster"), // Replace with your ECS cluster name
				Task:    aws.String(clientConn.TaskArn),
			})
			if err != nil {
				log.Errorf("Failed to stop client %s task: %v", clientID, err)
			} else {
				log.Infof("Stopped client %s task", clientID)
			}
		}
	}
	clientsMu.Unlock()
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
		log.Infof("Received address from client %s", clientID)
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
	ConnMu  sync.Mutex
	TaskArn string // Store the task ARN of the client
}
