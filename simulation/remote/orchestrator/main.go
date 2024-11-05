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

	var (
		tasksMu sync.Mutex
		tasks   []struct {
			ClientID string
			TaskArn  string
		}
	)
	g := new(errgroup.Group)
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
	log.Info("Waiting for clients to send addresses...")
	timeout := time.After(1 * time.Minute)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			log.Fatal("Timeout waiting for client addresses")
		case <-ticker.C:
			allReceived := true
			clientsMu.Lock()
			for _, clientID := range clientIDs {
				clientConn, exists := clients[clientID]
				if !exists || clientConn.Address == "" {
					log.Infof(
						"Client %s address not received (exists: %v, address: '%s')",
						clientID,
						exists,
						func() string {
							if exists {
								return clientConn.Address
							}
							return ""
						}(),
					)
					allReceived = false
					break
				}
			}
			clientsMu.Unlock()

			if allReceived {
				log.Info("All clients have sent their addresses")
				return
			}
		}
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
		log.Errorf("WebSocket upgrade error: %v", err)
		return
	}
	// Read client ID from query parameters
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		log.Error("Client ID not provided")
		conn.Close()
		return
	}

	clientsMu.Lock()
	clientConn, exists := clients[clientID]
	if !exists {
		clientConn = &ClientConnection{
			ID:      clientID,
			Conn:    conn,
			Address: "",
			ConnMu:  sync.Mutex{},
		}
		clients[clientID] = clientConn
	} else {
		clientConn.Conn = conn
	}
	clientsMu.Unlock()

	log.Infof("Client %s connected via WebSocket", clientID)

	// Listen for messages from the client
	go func() {
		defer conn.Close()
		for {
			var message ClientMessage
			err := conn.ReadJSON(&message)
			if err != nil {
				log.Errorf("Error reading from client %s: %v", clientID, err)
				break
			}
			handleClientMessage(clientID, message)
		}
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
		} else {
			log.Warnf("Client %s not found", clientID)
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

//time="2024-11-04T16:46:18Z" level=info msg="Simulation Version: 1.0\n"
//time="2024-11-04T16:46:18Z" level=info msg="ASP Network: regtest\n"
//time="2024-11-04T16:46:18Z" level=info msg="Number of Clients: 50\n"
//time="2024-11-04T16:46:18Z" level=info msg="Number of Rounds: 3\n"
//time="2024-11-04T16:46:18Z" level=info msg="Start building ARKD docker container ..."
//time="2024-11-04T16:46:28Z" level=info msg="ASP running..."
//time="2024-11-04T16:46:54Z" level=info msg="Orchestrator HTTP server running on port 9000"
//time="2024-11-04T16:46:54Z" level=info msg="Task Definition details: &{Compatibilities:[EC2 FARGATE] ContainerDefinitions:[{Command:[] Cpu:0 CredentialSpecs:[] DependsOn:[] DisableNetworking:<nil> DnsSearchDomains:[] DnsServers:[] DockerLabels:map[] DockerSecurityOptions:[] EntryPoint:[] Environment:[{Name:0xc000116390 Value:0xc0001163a0 noSmithyDocumentSerde:{}} {Name:0xc0001163b0 Value:0xc0001163c0 noSmithyDocumentSerde:{}}] EnvironmentFiles:[] Essential:0xc000014497 ExtraHosts:[] FirelensConfiguration:<nil> HealthCheck:<nil> Hostname:<nil> Image:0xc000116380 Interactive:<nil> Links:[] LinuxParameters:<nil> LogConfiguration:0xc00007e100 Memory:<nil> MemoryReservation:<nil> MountPoints:[] Name:0xc0001163d0 PortMappings:[] Privileged:<nil> PseudoTerminal:<nil> ReadonlyRootFilesystem:<nil> RepositoryCredentials:<nil> ResourceRequirements:[] RestartPolicy:<nil> Secrets:[] StartTimeout:<nil> StopTimeout:<nil> SystemControls:[] Ulimits:[] User:<nil> VolumesFrom:[] WorkingDirectory:<nil> noSmithyDocumentSerde:{}}] Cpu:0xc000116340 DeregisteredAt:<nil> EphemeralStorage:<nil> ExecutionRoleArn:0xc0001163e0 Family:0xc000116350 InferenceAccelerators:[] IpcMode: Memory:0xc0001164a0 NetworkMode:awsvpc PidMode: PlacementConstraints:[] ProxyConfiguration:<nil> RegisteredAt:2024-11-04 16:11:27.736 +0000 UTC RegisteredBy:0xc0001164b0 RequiresAttributes:[{Name:0xc000116400 TargetId:<nil> TargetType: Value:<nil> noSmithyDocumentSerde:{}} {Name:0xc000116410 TargetId:<nil> TargetType: Value:<nil> noSmithyDocumentSerde:{}} {Name:0xc000116420 TargetId:<nil> TargetType: Value:<nil> noSmithyDocumentSerde:{}} {Name:0xc000116430 TargetId:<nil> TargetType: Value:<nil> noSmithyDocumentSerde:{}} {Name:0xc000116440 TargetId:<nil> TargetType: Value:<nil> noSmithyDocumentSerde:{}} {Name:0xc000116450 TargetId:<nil> TargetType: Value:<nil> noSmithyDocumentSerde:{}} {Name:0xc000116460 TargetId:<nil> TargetType: Value:<nil> noSmithyDocumentSerde:{}} {Name:0xc000116470 TargetId:<nil> TargetType: Value:<nil> noSmithyDocumentSerde:{}} {Name:0xc000116480 TargetId:<nil> TargetType: Value:<nil> noSmithyDocumentSerde:{}}] RequiresCompatibilities:[FARGATE] Revision:15 RuntimePlatform:<nil> Status:ACTIVE TaskDefinitionArn:0xc000116360 TaskRoleArn:0xc0001163f0 Volumes:[] noSmithyDocumentSerde:{}}"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_18 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/bde971d7bbfe4bb1aa1e11b28d5f22ff"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_49 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/c5ce6ec044d24790844a2c1b9eea25fe"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_11 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/d75ecde646bc44e0a93b5fafcc9810ac"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_30 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/ba66d98341d44b3abddca72dbae59f96"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_43 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/f7bc9b42ec33470e99512a494008f6cd"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_39 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/bf2325546ba94372938d484263667e9c"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_31 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/cd982dba30c744889ede1cc0c123d9e9"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_37 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/cc0f3a6046714813b8b0a63fbe97069a"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_29 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/8fea3ca451734748abbb8938ef200337"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_32 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/3c492f90c04a4f2ab69af3e594ac322d"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_7 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/59d49d5d2c274649b825585eda2206be"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_12 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/0b7cca0539ab4a15823b4dc0f92e82bc"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_42 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/c258d3a95b5648f68543754dbb8d78ce"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_49 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_36 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/a5a6ac174f5e45718da7b43d539ea01f"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_4 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/1d29f35c1ae54bc39c30dfa4f428b2ef"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_18 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_41 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/bee9096157d94dd1b8f7c5c7158687a8"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_0 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/41231d5a596d4642914ebcbabdfd49ca"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_5 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/286a1b599e314bcda170dd01aab1f34a"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_11 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_44 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/2e3f73334e694ce68c81326b78f8aceb"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_47 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/98bc83d6ac044346944a5ec4fcfeed58"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_10 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/7051d94e3eb84e0f8af9f05e92fc5709"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_2 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/87e6e4da4f6b4842a673cd0135a93d38"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_48 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/ed8f101503b44c6e94c45c92c5fc0088"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_43 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_25 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/fa2b8544aeb547ddb91418ab9782b65d"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_22 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/6e34c024d0a04467a1b818497ea267b3"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_37 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_39 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_31 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_30 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_8 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/43b98e36e3a04e1f9a99914e09e68865"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_19 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/75fa5a73e39741f38e8ec416af6ba3fd"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_14 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/373e0c7ab9ec4b34801b867bb999c8c0"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_13 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/dc6745b961474b928c5384233fca8628"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_40 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/27aa720df01d48f4bff075a08ba8bd0d"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_7 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_27 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/a2b5e0c1958c458192f70c936f8b907d"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_29 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_32 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_42 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_3 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/ad2f602fc3ad4e84933d036bd0e10422"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_12 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_4 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_41 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_47 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_36 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_5 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_44 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_10 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_6 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/38995d15b58e4a258241f58f9c61c7c1"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_0 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_23 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/68db425367e84184b87bccfd5406b016"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_48 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_25 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_26 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/220b99643df944ab8257001ab0c88c69"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_2 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_22 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_21 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/29b58d3709dd4285b8eefcb4442cee56"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_20 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/b3843759c9034270ab0e3a9a97e34dde"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_46 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/788e64bbeee04af2bfd079c621bd31b6"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_15 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/1df7a5b23e6747f7b75db1a7e65420ba"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_19 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_1 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/8f319e53e5b34f6c97cebe61b05a7c0b"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_8 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_24 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/730a1ec7ce68494aaa0cfcc1d44dacd6"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_38 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/fef37bff713e42b5a7a6e37f74d150c4"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_14 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_13 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_27 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_17 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/e528efd2b865459fb77c4f7b0cae3d4d"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_28 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/80c0d34310a14d99bc083527d76d29ae"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_3 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_6 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_40 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_34 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/98fc8db405c9456099f400590143fc26"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_45 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/1be94b2963784af8806f61502c2861f3"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_23 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_26 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_21 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_15 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_20 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_35 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/39b57600d1994060a5e21a4e7f32f5c0"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_1 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_38 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_24 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_46 task status: PROVISIONING"
//time="2024-11-04T16:46:55Z" level=info msg="Started client client_9 with task ARN: arn:aws:ecs:eu-central-1:391147685145:task/OrchestratorCluster/41cb6a423776492c938cf004b419e80a"
//time="2024-11-04T16:46:55Z" level=info msg="Client client_28 task status: PROVISIONING"
//me="2024-11-04T16:47:07Z" level=info msg="Received address from client client_12"
//time="2024-11-04T16:47:07Z" level=info msg="Received address from client client_35"
//time="2024-11-04T16:47:07Z" level=info msg="Received address from client client_28"
//time="2024-11-04T16:47:07Z" level=info msg="Received address from client client_41"
//time="2024-11-04T16:47:07Z" level=info msg="Received address from client client_5"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_32"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_31"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_20"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_21"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_11"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_23"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_39"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_44"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_1"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_27"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_48"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_15"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_8"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_26"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_36"
//time="2024-11-04T16:47:08Z" level=info msg="Received address from client client_40"
//time="2024-11-04T16:47:09Z" level=info msg="Received address from client client_24"
//time="2024-11-04T16:47:09Z" level=info msg="Received address from client client_33"
//time="2024-11-04T16:47:09Z" level=info msg="Received address from client client_49"
//time="2024-11-04T16:47:09Z" level=info msg="Received address from client client_46"
//time="2024-11-04T16:47:09Z" level=info msg="Received address from client client_18"
//time="2024-11-04T16:47:09Z" level=info msg="Received address from client client_22"
//time="2024-11-04T16:47:10Z" level=info msg="Received address from client client_42"
//time="2024-11-04T16:47:10Z" level=info msg="Received address from client client_7"
//time="2024-11-04T16:47:10Z" level=info msg="Received address from client client_17"
//time="2024-11-04T16:47:10Z" level=info msg="Received address from client client_0"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_49 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_37 task status: PENDING"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_18 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_43 task status: PENDING"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_30 task status: PENDING"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_31 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_42 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_11 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_39 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_7 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_32 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_29 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_0 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_10 task status: PENDING"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_19 task status: PENDING"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_14 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_12 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_44 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Received address from client client_4"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_36 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_48 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_5 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_8 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_41 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_3 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_13 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_21 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_47 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_2 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_6 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_22 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_20 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_25 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_4 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_26 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_27 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_17 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_40 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_15 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_28 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_46 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Received address from client client_43"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_35 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_34 task status: PENDING"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_38 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_23 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_45 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_9 task status: PENDING"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_1 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_33 successfully started and running"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_16 task status: PENDING"
//time="2024-11-04T16:47:10Z" level=info msg="Client client_24 successfully started and running"
//time="2024-11-04T16:47:11Z" level=info msg="Received address from client client_16"
//time="2024-11-04T16:47:12Z" level=info msg="Received address from client client_30"
//time="2024-11-04T16:47:12Z" level=info msg="Received address from client client_9"
//time="2024-11-04T16:47:14Z" level=info msg="Received address from client client_34"
//time="2024-11-04T16:47:15Z" level=info msg="Client client_37 successfully started and running"
//time="2024-11-04T16:47:15Z" level=info msg="Client client_43 successfully started and running"
//time="2024-11-04T16:47:15Z" level=info msg="Client client_30 successfully started and running"
//time="2024-11-04T16:47:15Z" level=info msg="Client client_19 successfully started and running"
//time="2024-11-04T16:47:15Z" level=info msg="Client client_10 successfully started and running"
//time="2024-11-04T16:47:15Z" level=info msg="Client client_34 successfully started and running"
//time="2024-11-04T16:47:15Z" level=info msg="Client client_9 successfully started and running"
//time="2024-11-04T16:47:15Z" level=info msg="Client client_16 successfully started and running"
//time="2024-11-04T16:47:15Z" level=info msg="All clients started successfully"
//time="2024-11-04T16:47:15Z" level=info msg="Waiting for clients to send addresses..."
//time="2024-11-04T16:47:15Z" level=info msg="Current state of clients map:"
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_31, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_25, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_37, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_14, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_12, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_8, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_18, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_42, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_19, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_9, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_0, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_4, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_3, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_13, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_38, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_16, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_30, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_17, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_20, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_11, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_27, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_15, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_36, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_40, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_33, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_32, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_39, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_49, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_47, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_43, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_34, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_10, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_45, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_35, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_28, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_41, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_5, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_44, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_1, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_24, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_23, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_48, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_6, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_21, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_26, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_46, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_22, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_7, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_29, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client ID: client_2, Address: "
//time="2024-11-04T16:47:15Z" level=info msg="Client client_0 address not received"
//time="2024-11-04T16:47:16Z" level=info msg="Current state of clients map:"
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_4, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_3, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_13, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_38, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_16, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_30, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_9, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_0, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_11, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_27, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_15, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_36, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_40, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_33, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_17, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_20, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_39, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_49, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_47, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_43, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_34, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_10, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_32, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_28, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_41, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_5, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_44, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_1, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_24, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_45, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_35, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_48, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_23, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_26, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_46, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_22, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_7, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_29, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_2, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_6, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_21, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_25, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_37, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_31, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_12, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_8, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_18, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_42, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_19, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client ID: client_14, Address: "
//time="2024-11-04T16:47:16Z" level=info msg="Client client_0 address not received"
//time="2024-11-04T16:47:17Z" level=info msg="Current state of clients map:"
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_12, Address: "
//:
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_18, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_42, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_19, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_14, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_4, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_3, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_13, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_38, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_16, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_30, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_9, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_0, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_11, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_27, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_15, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_36, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_40, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_33, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_17, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_20, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_39, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_49, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_47, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_43, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_34, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_10, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_32, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_28, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_41, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_5, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_44, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_1, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_24, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_45, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_35, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_48, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_23, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_26, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_46, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_22, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_7, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_29, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_2, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_6, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_21, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_25, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_37, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client ID: client_31, Address: "
//time="2024-11-04T16:47:17Z" level=info msg="Client client_0 address not received"
//time="2024-11-04T16:47:18Z" level=info msg="Current state of clients map:"
//time="2024-11-04T16:47:18Z" level=info msg="Client ID: client_23, Address: "
//time="2024-11-04T16:47:18Z" level=info msg="Client ID: client_48, Address: "
//time="2024-11-04T16:47:18Z" level=info msg="Client ID: client_22, Address:
