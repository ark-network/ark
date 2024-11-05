package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/xeipuuv/gojsonschema"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	utils "github.com/ark-network/ark/server/test/e2e"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecsTypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"sigs.k8s.io/yaml"
)

const (
	composePath    = "../../../docker-compose.clark.regtest.yml"
	schemaPath     = "../../schema.yaml"
	simulationPath = "../../simulation.yaml"
	defaultAspUrl  = "localhost:7070"
	clientPort     = "9000" // All clients listen on this port
)

type ClientInfo struct {
	ID        string
	Address   string
	TaskARN   string
	IPAddress string
}

var (
	clients   = make(map[string]*ClientInfo)
	clientsMu sync.Mutex
)

func main() {
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

	simulation, err := loadAndValidateSimulation(*simFile)
	if err != nil {
		log.Fatalf("Error loading simulation config: %v", err)
	}

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

	// Wait for clients to send their addresses
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

func startServer() {
	http.HandleFunc("/address", addressHandler)
	http.HandleFunc("/faucet", faucetHandler)
	log.Infoln("Orchestrator HTTP server running on port 9000")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Fatalf("Orchestrator server failed: %v", err)
	}
}

func addressHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientID string `json:"client_id"`
		Address  string `json:"address"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Errorf("Error decoding address request: %v", err)
		return
	}

	clientsMu.Lock()
	if client, exists := clients[req.ClientID]; exists {
		client.Address = req.Address
		log.Infof("Registered address for client %s: %s", req.ClientID, req.Address)
	} else {
		log.Warnf("Received address for unknown client: %s", req.ClientID)
	}
	clientsMu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func faucetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Address string `json:"address"`
		Amount  string `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Errorf("Error decoding faucet request: %v", err)
		return
	}

	if _, err := utils.RunCommand("nigiri", "faucet", req.Address, fmt.Sprintf("%.8f", req.Amount)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Errorf("Error running faucet command: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
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

					if err := executeClientAction(clientID, actionType, action); err != nil {
						log.Warnf("Error executing %s for client %s: %v", actionType, clientID, err)
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

func executeClientAction(clientID string, actionType string, action ActionMap) error {
	clientsMu.Lock()
	client, exists := clients[clientID]
	clientsMu.Unlock()

	if !exists {
		return fmt.Errorf("client %s not found", clientID)
	}

	clientURL := fmt.Sprintf("http://%s:%s", client.IPAddress, clientPort)

	switch actionType {
	case "Onboard":
		amount, _ := action["amount"].(float64)
		return executeOnboard(clientURL, amount)
	case "SendAsync":
		amount, _ := action["amount"].(float64)
		toClientID, _ := action["to"].(string)
		toAddress, err := getClientAddress(toClientID)
		if err != nil {
			return err
		}
		return executeSendAsync(clientURL, amount, toAddress)
	case "Claim":
		return executeClaim(clientURL)
	default:
		return fmt.Errorf("unknown action type: %s", actionType)
	}
}

func getClientAddress(clientID string) (string, error) {
	clientsMu.Lock()
	defer clientsMu.Unlock()

	client, exists := clients[clientID]
	if !exists {
		return "", fmt.Errorf("client %s not found", clientID)
	}
	if client.Address == "" {
		return "", fmt.Errorf("address for client %s not available", clientID)
	}
	return client.Address, nil
}

func executeOnboard(clientURL string, amount float64) error {
	payload := map[string]float64{"amount": amount}
	return sendRequest(clientURL+"/onboard", payload)
}

func executeSendAsync(clientURL string, amount float64, toAddress string) error {
	payload := map[string]interface{}{
		"amount":     amount,
		"to_address": toAddress,
	}
	return sendRequest(clientURL+"/sendAsync", payload)
}

func executeClaim(clientURL string) error {
	return sendRequest(clientURL+"/claim", nil)
}

func sendRequest(url string, payload interface{}) error {
	var jsonData []byte
	var err error
	if payload != nil {
		jsonData, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// startClients launches each client as an AWS Fargate task.
func startClients(subnetIDsEnv, securityGroupIDsEnv string, clientConfigs []ClientConfig) error {
	awsRegion := "eu-central-1"
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
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

			ip, err := waitForTaskRunningAndGetIP(ctx, ecsClient, clusterName, taskArn)
			if err != nil {
				return fmt.Errorf("error waiting for client %s task: %v", clientID, err)
			}

			clientsMu.Lock()
			clients[clientID] = &ClientInfo{
				ID:        clientID,
				TaskARN:   taskArn,
				IPAddress: ip,
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

func waitForTaskRunningAndGetIP(ctx context.Context, ecsClient *ecs.Client, clusterName, taskArn string) (string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("timeout waiting for task to start")
		default:
			describeTasksInput := &ecs.DescribeTasksInput{
				Cluster: aws.String(clusterName),
				Tasks:   []string{taskArn},
			}

			result, err := ecsClient.DescribeTasks(ctx, describeTasksInput)
			if err != nil {
				return "", fmt.Errorf("failed to describe task: %v", err)
			}

			if len(result.Tasks) > 0 {
				task := result.Tasks[0]
				status := aws.ToString(task.LastStatus)

				switch status {
				case "RUNNING":
					if task.TaskArn != nil && len(task.Attachments) > 0 {
						for _, attachment := range task.Attachments {
							if aws.ToString(attachment.Type) == "ElasticNetworkInterface" {
								for _, detail := range attachment.Details {
									if aws.ToString(detail.Name) == "privateIPv4Address" {
										return aws.ToString(detail.Value), nil
									}
								}
							}
						}
					}
					return "", fmt.Errorf("could not find IP address for task")
				case "STOPPED":
					var errorDetail string
					if task.StoppedReason != nil {
						errorDetail = *task.StoppedReason
					}
					for _, container := range task.Containers {
						if container.Reason != nil {
							errorDetail += fmt.Sprintf(" Container error: %s", *container.Reason)
						}
					}
					return "", fmt.Errorf("task stopped: %s", errorDetail)
				}
			}

			time.Sleep(5 * time.Second)
		}
	}
}

func waitForClientsToSendAddresses(clientIDs []string) {
	log.Info("Waiting for clients to send addresses...")
	timeout := time.After(2 * time.Minute)
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
				client, exists := clients[clientID]
				if !exists || client.Address == "" {
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

func stopClients() {
	awsRegion := "eu-central-1"
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithRegion(awsRegion),
	)
	if err != nil {
		log.Errorf("Unable to load AWS SDK config: %v", err)
		return
	}

	ecsClient := ecs.NewFromConfig(cfg)

	clientsMu.Lock()
	defer clientsMu.Unlock()

	for _, client := range clients {
		if client.TaskARN != "" {
			_, err := ecsClient.StopTask(context.TODO(), &ecs.StopTaskInput{
				Cluster: aws.String("OrchestratorCluster"),
				Task:    aws.String(client.TaskARN),
			})
			if err != nil {
				log.Errorf("Failed to stop client %s task: %v", client.ID, err)
			} else {
				log.Infof("Stopped client %s task", client.ID)
			}
		}
	}
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
