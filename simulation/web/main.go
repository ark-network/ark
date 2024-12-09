package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecsTypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"golang.org/x/sync/errgroup"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	log "github.com/sirupsen/logrus"
	"github.com/xeipuuv/gojsonschema"

	servicequotasTypes "github.com/aws/aws-sdk-go-v2/service/servicequotas/types"
	"sigs.k8s.io/yaml"
)

const (
	clientPort = "9000"
)

//go:embed templates/*
var content embed.FS

var (
	templates           *template.Template
	clients             = make(map[string]*ClientInfo)
	clientsMu           sync.Mutex
	username            string
	password            string
	sessionStore        *sessions.CookieStore
	subnetIDsEnv        = flag.String("subnet", "", "Comma-separated list of subnet IDs")
	securityGroupIDsEnv = flag.String("sg", "", "Comma-separated list of security group IDs")
	outputChan          chan string
	simulationActive    bool
	simulationMu        sync.Mutex
)

func main() {
	flag.StringVar(&username, "user", "admin", "Username for authentication")
	flag.StringVar(&password, "pass", "admin", "Password for authentication")
	flag.Parse()

	if *subnetIDsEnv == "" || *securityGroupIDsEnv == "" {
		log.Fatal("Both subnet IDs (-subnet) and security group IDs (-sg) must be provided")
	}

	sessionStore = sessions.NewCookieStore([]byte("your-secret-key"))

	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		// Secure: true, // Uncomment this if using HTTPS
	}

	var err error
	templates, err = template.ParseFS(content, "templates/*.html")
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()
	r.Use(panicRecoveryMiddleware)
	r.HandleFunc("/login", handleLogin).Methods("GET", "POST")
	r.HandleFunc("/logout", handleLogout).Methods("GET")
	r.HandleFunc("/", authMiddleware(handleIndex)).Methods("GET")
	r.HandleFunc("/run", authMiddleware(handleRun)).Methods("GET", "POST")
	r.HandleFunc("/simulation", authMiddleware(handleSimulation)).Methods("GET", "POST")
	r.HandleFunc("/address", addressHandler).Methods("GET", "POST")
	r.HandleFunc("/log", logHandler).Methods("GET", "POST")

	port := "9000"
	log.Infof("Starting server on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func panicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Errorf("Recovered from panic: %v\n%s", rec, debug.Stack())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := sessionStore.Get(r, "auth-session")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if err := templates.ExecuteTemplate(w, "login.html", nil); err != nil {
			log.Errorf("Error rendering login template: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Errorf("Error parsing form: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	user := r.FormValue("username")
	pass := r.FormValue("password")

	if user == username && pass == password {
		session, _ := sessionStore.Get(r, "auth-session")
		session.Values["authenticated"] = true
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	} else {
		data := PageData{
			ErrorMessage: "Invalid username or password",
		}
		if err := templates.ExecuteTemplate(w, "login.html", data); err != nil {
			log.Errorf("Error rendering login template: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "auth-session")
	session.Values["authenticated"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func getSimulationFiles() ([]string, error) {
	files, err := os.ReadDir("./config")
	if err != nil {
		return nil, err
	}

	var simFiles []string
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		if strings.HasSuffix(name, ".yaml") && name != "schema.yaml" {
			simFiles = append(simFiles, name)
		}
	}
	return simFiles, nil
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	simFiles, err := getSimulationFiles()
	if err != nil {
		log.Errorf("Error getting simulation files: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := PageData{
		SimulationFiles: simFiles,
	}

	if err := templates.ExecuteTemplate(w, "index.html", data); err != nil {
		log.Errorf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func handleRun(w http.ResponseWriter, r *http.Request) {
	simulationMu.Lock()
	if simulationActive {
		simulationMu.Unlock()
		http.Error(w, "A simulation is already running", http.StatusConflict)
		return
	}
	simulationActive = true
	outputChan = make(chan string, 1000)
	simulationMu.Unlock()
	defer func() {
		simulationMu.Lock()
		simulationActive = false
		outputChan = nil
		simulationMu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Errorf("Streaming not supported")
		fmt.Fprintf(w, "event: error\ndata: Streaming not supported\n\n")
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Errorf("Error parsing form: %v", err)
		fmt.Fprintf(w, "event: error\ndata: Failed to parse form\n\n")
		flusher.Flush()
		return
	}

	aspUrl := r.Form.Get("asp_url")
	if aspUrl == "" {
		log.Errorf("ASP URL is required")
		fmt.Fprintf(w, "event: error\ndata: ASP URL is required\n\n")
		flusher.Flush()
		return
	}

	explorerUrl := r.Form.Get("explorer_url")
	if explorerUrl == "" {
		log.Errorf("Explorer URL is required")
		fmt.Fprintf(w, "event: error\ndata: Explorer URL is required\n\n")
		flusher.Flush()
		return
	}

	simulationFile := r.Form.Get("simulation_file")
	if simulationFile == "" {
		log.Errorf("Simulation file is required")
		fmt.Fprintf(w, "event: error\ndata: Simulation file is required\n\n")
		flusher.Flush()
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	simulationJobDone := make(chan struct{})
	go runSimulation(ctx, simulationFile, aspUrl, explorerUrl, outputChan, simulationJobDone)

	pingTicker := time.NewTicker(10 * time.Second)
	defer pingTicker.Stop()

	reqCtxDone := false
	for {
		select {
		case <-ctx.Done():
			log.Infof("Request context done")
			reqCtxDone = true
		case <-pingTicker.C:
			if _, err := fmt.Fprintf(w, "event: ping\ndata: \n\n"); err != nil {
				log.Warnf("Error sending ping: %v", err)
			}
			flusher.Flush()
		case msg, ok := <-outputChan:
			if !ok {
				return
			}

			if !reqCtxDone {
				if _, err := fmt.Fprintf(w, "event: message\n"); err != nil {
					log.Warnf("Error sending message: %v", err)
					cancel()
					return
				}
				lines := strings.Split(msg, "\n")
				for _, line := range lines {
					if _, err := fmt.Fprintf(w, "data: %s\n", line); err != nil {
						log.Warnf("Error sending data msg: %v", err)
						cancel()
						return
					}
				}
				if _, err := fmt.Fprintf(w, "\n"); err != nil {
					log.Warnf("Error sending newline: %v", err)
					cancel()
					return
				}
				flusher.Flush()
			}

		case <-simulationJobDone:
			simulationMu.Lock()
			simulationActive = false
			close(outputChan)
			outputChan = nil
			simulationMu.Unlock()
			if _, err := fmt.Fprintf(w, "event: close\ndata: stream closed\n\n"); err != nil {
				log.Warnf("Error sending end msg: %v", err)
				cancel()
				return
			}
			flusher.Flush()
			log.Infof("Simulation job done")
			return
		}
	}
}

func runSimulation(
	ctx context.Context,
	simulationFile, aspUrl, explorerUrl string,
	outputChan chan string, simulationJobDone chan struct{},
) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Panic in runSimulation: %v", r)
		}
		simulationJobDone <- struct{}{}
	}()

	sendToFrontend("Starting simulation...")

	simulationContent, err := os.ReadFile(fmt.Sprintf("./config/%s", simulationFile))
	if err != nil {
		sendToFrontend(fmt.Sprintf("Error reading simulation file: %v", err))
		return
	}

	simulation, err := validateSimulation(simulationContent)
	if err != nil {
		sendToFrontend(fmt.Sprintf("Invalid simulation file: %v", err))
		return
	}

	err = startClients(ctx, aspUrl, explorerUrl, *subnetIDsEnv, *securityGroupIDsEnv, simulation.Clients, outputChan)
	if err != nil {
		sendToFrontend(fmt.Sprintf("Error starting clients: %v", err))
		return
	}
	sendToFrontend("Successfully started all clients")

	clientIDs := make([]string, len(simulation.Clients))
	for i, client := range simulation.Clients {
		clientIDs[i] = client.ID
	}

	sendToFrontend("Waiting for clients to send addresses...")
	waitForClientsToSendAddresses(ctx, clientIDs)
	sendToFrontend("All clients have sent their addresses")

	sendToFrontend("Starting simulation execution...")
	executeSimulation(ctx, simulation, outputChan)
	sendToFrontend("Simulation execution completed")

	sendToFrontend("Stopping clients...")
	stopClients(ctx)
	sendToFrontend("All clients stopped")

	sendToFrontend("Simulation completed successfully")
}

func handleSimulation(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleSimulationGet(w, r)
	case http.MethodPost:
		handleSimulationPost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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

func logHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	simulationMu.Lock()
	active := simulationActive
	simulationMu.Unlock()

	if !active {
		http.Error(w, "No active simulation to receive logs", http.StatusBadRequest)
		return
	}

	var req struct {
		ClientID string `json:"client_id"`
		Type     string `json:"type"`
		Message  string `json:"message"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Errorf("Error decoding log request: %v", err)
		return
	}

	logMsg := fmt.Sprintf("Client %s: %s", req.ClientID, req.Message)
	switch req.Type {
	case "Error":
		log.Warnln(logMsg)
		sendToFrontend(fmt.Sprintf("Error: %s", logMsg))
	case "Info":
		log.Infoln(logMsg)
		sendToFrontend(logMsg)
	default:
		log.Warnf("Unknown log type: %s", req.Type)
	}

	w.WriteHeader(http.StatusOK)
}

func sendToFrontend(msg string) {
	simulationMu.Lock()
	defer simulationMu.Unlock()
	if outputChan != nil {
		outputChan <- msg
	}
}

func handleSimulationGet(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("type") == "schema" {
		content, err := os.ReadFile("./config/schema.yaml")
		if err != nil {
			log.WithError(err).Error("Failed to read simulation file")
			http.Error(w, "Error reading simulation file", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, `<pre><code class="language-yaml">%s</code></pre>
			<script>
				hljs.highlightElement(document.querySelector('#simulation-preview code'));
				// Ensure proper height
				document.querySelector('#simulation-preview').style.height = 'auto';
			</script>`, content)
		return
	}

	simulationFile := r.URL.Query().Get("file")
	if simulationFile == "" {
		simFiles, err := getSimulationFiles()
		if err != nil {
			log.WithError(err).Error("Failed to get simulation files")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		for _, file := range simFiles {
			selected := ""
			if file == "simulation.yaml" {
				selected = " selected"
			}
			fmt.Fprintf(w, `<option value="%s"%s>%s</option>`, file, selected, file)
		}
		return
	}

	content, err := os.ReadFile(fmt.Sprintf("./config/%s", simulationFile))
	if err != nil {
		log.WithError(err).WithField("file", simulationFile).Error("Failed to read simulation file")
		http.Error(w, "Error reading simulation file", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(content)
}

func handleSimulationPost(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "multipart/form-data") {
		log.WithField("content-type", contentType).Error("Invalid content type for simulation upload")
		http.Error(w, "Invalid request: expected multipart/form-data", http.StatusBadRequest)
		return
	}

	err := r.ParseMultipartForm(10 << 20) // 10 MB max
	if err != nil {
		log.WithError(err).Error("Failed to parse multipart form")
		http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		log.WithError(err).Error("Failed to get file from form")
		http.Error(w, "Failed to get file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		log.WithError(err).WithField("filename", handler.Filename).Error("Failed to read file content")
		http.Error(w, "Failed to read file: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, err = validateSimulation(content)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"filename":       handler.Filename,
			"content_length": len(content),
		}).Error("Simulation validation failed")
		http.Error(w, fmt.Sprintf("Invalid simulation file: %v", err), http.StatusBadRequest)
		return
	}

	err = os.WriteFile(fmt.Sprintf("./config/%s", handler.Filename), content, 0644)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"filename": handler.Filename,
			"path":     "./config/simulations/" + handler.Filename,
		}).Error("Failed to save simulation file")
		http.Error(w, "Failed to save file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.WithFields(log.Fields{
		"filename": handler.Filename,
		"size":     len(content),
	}).Info("Successfully uploaded and validated simulation file")

	w.Header().Set("X-File-Uploaded", "true")

	handleSimulationGet(w, r)
}

func validateSimulation(content []byte) (*Simulation, error) {
	schemaContent, err := os.ReadFile("./config/schema.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read schema file: %v", err)
	}

	jsonSchema, err := yaml.YAMLToJSON(schemaContent)
	if err != nil {
		return nil, fmt.Errorf("failed to convert schema to JSON: %v", err)
	}

	jsonContent, err := yaml.YAMLToJSON(content)
	if err != nil {
		return nil, fmt.Errorf("invalid YAML format: %v", err)
	}

	schemaLoader := gojsonschema.NewBytesLoader(jsonSchema)
	documentLoader := gojsonschema.NewBytesLoader(jsonContent)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return nil, fmt.Errorf("validation error: %v", err)
	}

	if !result.Valid() {
		var errorMsgs []string
		for _, desc := range result.Errors() {
			errorMsgs = append(errorMsgs, desc.String())
		}
		return nil, fmt.Errorf("%s", strings.Join(errorMsgs, "; "))
	}

	var simulation Simulation
	if err := yaml.Unmarshal(content, &simulation); err != nil {
		return nil, fmt.Errorf("failed to parse simulation YAML: %v", err)
	}

	return &simulation, nil
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

func startClients(
	ctx context.Context,
	aspUrl, explorerUrl, subnetID, securityGroup string,
	clientConfigs []ClientConfig, outputChan chan string,
) error {
	if err := checkECSQuotas(ctx, len(clientConfigs)); err != nil {
		return err
	}

	awsRegion := "eu-central-1"
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(awsRegion),
	)
	if err != nil {
		return fmt.Errorf("unable to load AWS SDK config: %v", err)
	}

	ecsClient := ecs.NewFromConfig(cfg)

	clusterName := "OrchestratorCluster"
	taskDefinition := "ClientTaskDefinition"

	describeTaskDefInput := &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: aws.String(taskDefinition),
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	g, gctx := errgroup.WithContext(ctxWithTimeout)

	taskDefDetails, err := ecsClient.DescribeTaskDefinition(gctx, describeTaskDefInput)
	if err != nil {
		outputChan <- fmt.Sprintf("Warning: Failed to get task definition details: %v", err)
		log.Warnf("Failed to get task definition details: %v", err)
	} else {
		outputChan <- fmt.Sprintf("Task Definition details: %+v", taskDefDetails.TaskDefinition)
		log.Infof("Task Definition details: %+v", taskDefDetails.TaskDefinition)
	}

	waitForTaskRunning := func(taskArn string, clientID string) error {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-gctx.Done():
				// If gctx is canceled (either timeout or parent cancel), return immediately
				return gctx.Err()
			case <-ticker.C:
				describeTasksInput := &ecs.DescribeTasksInput{
					Cluster: aws.String(clusterName),
					Tasks:   []string{taskArn},
				}

				result, err := ecsClient.DescribeTasks(gctx, describeTasksInput)
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
						var errorDetail string
						if task.StoppedReason != nil {
							errorDetail = *task.StoppedReason
						}

						for _, container := range task.Containers {
							if container.Reason != nil {
								errorDetail += fmt.Sprintf(" Container error: %s", *container.Reason)
							}
						}

						return fmt.Errorf("task stopped: %s", errorDetail)
					case "PENDING", "PROVISIONING":
						outputChan <- fmt.Sprintf("Client %s task status: %s", clientID, status)
						log.Infof("Client %s task status: %s", clientID, status)
					default:
						outputChan <- fmt.Sprintf("Client %s unexpected status: %s", clientID, status)
						log.Infof("Client %s unexpected status: %s", clientID, status)
					}
				}

				time.Sleep(3 * time.Second)
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

	for _, client := range clientConfigs {
		select {
		case <-gctx.Done():
			return gctx.Err()
		default:
		}

		client := client
		g.Go(func() error {
			clientID := client.ID
			outputChan <- fmt.Sprintf("Starting client %s...", clientID)

			clientEnvVars := []ecsTypes.KeyValuePair{
				{Name: aws.String("CLIENT_ID"), Value: aws.String(clientID)},
				{Name: aws.String("SIGNET_ASP_URL"), Value: aws.String(aspUrl)},
				{Name: aws.String("SIGNET_EXPLORER_URL"), Value: aws.String(explorerUrl)},
			}

			containerOverrides := ecsTypes.ContainerOverride{
				Name:        aws.String("ClientContainer"),
				Environment: clientEnvVars,
			}

			runTaskInput := &ecs.RunTaskInput{
				Cluster:        aws.String(clusterName),
				LaunchType:     ecsTypes.LaunchTypeFargate,
				TaskDefinition: aws.String(taskDefinition),
				NetworkConfiguration: &ecsTypes.NetworkConfiguration{
					AwsvpcConfiguration: &ecsTypes.AwsVpcConfiguration{
						Subnets:        []string{subnetID},
						SecurityGroups: []string{securityGroup},
						AssignPublicIp: ecsTypes.AssignPublicIpEnabled,
					},
				},
				Overrides: &ecsTypes.TaskOverride{
					ContainerOverrides: []ecsTypes.ContainerOverride{containerOverrides},
				},
			}

			backoff := 2 * time.Second
			var result *ecs.RunTaskOutput
			for i := 0; i < 5; i++ {
				select {
				case <-gctx.Done():
					return gctx.Err()
				default:
				}

				result, err = ecsClient.RunTask(gctx, runTaskInput)
				if err != nil {
					return fmt.Errorf("failed to start client %s: %v", clientID, err)
				}

				if len(result.Failures) > 0 {
					for _, failure := range result.Failures {
						outputChan <- fmt.Sprintf("Warning: Failed to start client %s: %s, %s",
							clientID, aws.ToString(failure.Reason), aws.ToString(failure.Detail))
						log.Warnf("Failed to start client %s: %s, %s",
							clientID, aws.ToString(failure.Reason), aws.ToString(failure.Detail))
					}
					time.Sleep(backoff)
					backoff *= 2
					continue
				}

				if len(result.Tasks) > 0 {
					break
				}

				outputChan <- fmt.Sprintf("Warning: No tasks created for client %s, retrying... (%d/5)", clientID, i+1)
				log.Warnf("No tasks created for client %s, retrying... (%d/5)", clientID, i+1)
				time.Sleep(backoff)
				backoff *= 2
			}

			if len(result.Tasks) == 0 {
				return fmt.Errorf("no tasks created for client %s after 5 attempts", clientID)
			}

			taskArn := *result.Tasks[0].TaskArn
			outputChan <- fmt.Sprintf("Started client %s with task ARN: %s", clientID, taskArn)
			log.Infof("Started client %s with task ARN: %s", clientID, taskArn)

			tasksMu.Lock()
			tasks = append(tasks, struct {
				ClientID string
				TaskArn  string
			}{
				ClientID: clientID,
				TaskArn:  taskArn,
			})
			tasksMu.Unlock()

			if err := waitForTaskRunning(taskArn, clientID); err != nil {
				return fmt.Errorf("client %s failed to start: %v", clientID, err)
			}

			ip, err := waitForTaskRunningAndGetIP(gctx, ecsClient, clusterName, taskArn)
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

			outputChan <- fmt.Sprintf("Client %s successfully started and running with IP: %s", clientID, ip)
			log.Infof("Client %s successfully started and running", clientID)
			return nil
		})

		time.Sleep(1 * time.Second)
	}

	g.Go(func() error {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-gctx.Done():
				// Stop when context is canceled
				return gctx.Err()
			case <-ticker.C:
				tasksMu.Lock()
				currentTasks := make([]struct {
					ClientID string
					TaskArn  string
				}, len(tasks))
				copy(currentTasks, tasks)
				tasksMu.Unlock()

				for _, task := range currentTasks {
					select {
					case <-gctx.Done():
						return gctx.Err()
					default:
					}

					describeTasksInput := &ecs.DescribeTasksInput{
						Cluster: aws.String(clusterName),
						Tasks:   []string{task.TaskArn},
					}

					result, err := ecsClient.DescribeTasks(gctx, describeTasksInput)
					if err != nil {
						outputChan <- fmt.Sprintf("Warning: Failed to describe task for client %s: %v", task.ClientID, err)
						log.Warnf("Failed to describe task for client %s: %v", task.ClientID, err)
						continue
					}

					if len(result.Tasks) > 0 {
						status := aws.ToString(result.Tasks[0].LastStatus)
						outputChan <- fmt.Sprintf("Client %s task status: %s", task.ClientID, status)
						if status == "STOPPED" {
							outputChan <- fmt.Sprintf("Warning: Client %s task stopped unexpectedly", task.ClientID)
						}
					}
				}
			}
		}
	})

	if err := g.Wait(); err != nil {
		outputChan <- fmt.Sprintf("Error starting clients: %v", err)
		log.Errorf("Error starting clients: %v", err)
		stopClients(ctx)
		return err
	}

	outputChan <- "All clients started successfully"
	log.Infof("All clients started successfully")
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
				if status == "RUNNING" {
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
				}
			}

			time.Sleep(5 * time.Second)
		}
	}
}

func waitForClientsToSendAddresses(ctx context.Context, clientIDs []string) {
	log.Info("Waiting for clients to send addresses...")
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctxWithTimeout.Done():
			if errors.Is(ctxWithTimeout.Err(), context.DeadlineExceeded) {
				log.Infof("waitForClientsToSendAddresses: context deadline exceeded, stopping startClients")
			} else if errors.Is(ctxWithTimeout.Err(), context.Canceled) {
				log.Infof("waitForClientsToSendAddresses: parent context canceled, stopping startClients")
			}
			return
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

func stopClients(ctx context.Context) {
	awsRegion := "eu-central-1"
	cfg, err := config.LoadDefaultConfig(
		ctx,
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
			_, err := ecsClient.StopTask(ctx, &ecs.StopTaskInput{
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

type ClientInfo struct {
	ID        string
	Address   string
	TaskARN   string
	IPAddress string
}

type PageData struct {
	SimulationFiles []string
	ErrorMessage    string
}

func executeSimulation(ctx context.Context, simulation *Simulation, outputChan chan string) {
	for i, round := range simulation.Rounds {
		select {
		case <-ctx.Done():
			outputChan <- "Simulation canceled"
			return
		default:
		}

		now := time.Now()
		roundMsg := fmt.Sprintf("Executing Round %d at %s", round.Number, now.Format("2006-01-02 15:04:05"))
		outputChan <- roundMsg
		var wg sync.WaitGroup
		for clientID, actions := range round.Actions {
			wg.Add(1)
			go func(clientID string, actions []ActionMap) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					outputChan <- fmt.Sprintf("Execution canceled for client %s", clientID)
					return
				default:
				}

				for _, action := range actions {
					actionType, ok := action["type"].(string)
					if !ok {
						outputChan <- fmt.Sprintf("Warning: Invalid action type for client %s", clientID)
						return
					}

					ctxWithTimeout, cancel := context.WithTimeout(
						ctx,
						3*time.Minute,
					)
					defer cancel()

					if err := executeClientAction(ctxWithTimeout, clientID, actionType, action); err != nil {
						outputChan <- fmt.Sprintf("Warning: Error executing %s for client %s: %v", actionType, clientID, err)
					} else {
						outputChan <- fmt.Sprintf("Successfully executed %s for client %s", actionType, clientID)
					}
				}
			}(clientID, actions)
		}
		wg.Wait()

		if i == len(simulation.Rounds)-1 {
			outputChan <- fmt.Sprintf("Simulation completed in %s", time.Since(now))
			return
		}

		sleepTime := 5 * time.Second
		outputChan <- fmt.Sprintf("Waiting for %s before starting next round", sleepTime)
		time.Sleep(sleepTime)
		outputChan <- fmt.Sprintf("Round %d completed at %s", round.Number, time.Now().Format("2006-01-02 15:04:05"))
	}
}

func executeClientAction(ctx context.Context, clientID string, actionType string, action ActionMap) error {
	clientsMu.Lock()
	client, exists := clients[clientID]
	clientsMu.Unlock()

	if !exists {
		return fmt.Errorf("client %s not found", clientID)
	}

	clientURL := fmt.Sprintf("http://%s:%s", client.IPAddress, clientPort)

	switch actionType {
	case "Onboard":
		amount, on := action["amount"].(float64)
		if !on {
			return fmt.Errorf("invalid amount in onboard action")
		}
		return executeOnboard(ctx, clientURL, amount)
	case "SendAsync":
		amount, _ := action["amount"].(int64)
		toClientID, _ := action["to"].(string)
		toAddress, err := getClientAddress(toClientID)
		if err != nil {
			return err
		}
		return executeSendAsync(ctx, clientURL, amount, toAddress)
	case "Claim":
		return executeClaim(ctx, clientURL)
	case "Balance":
		return executeBalance(ctx, clientURL)
	case "Redeem":
		force, ok := action["force"].(bool)
		if !ok {
			return fmt.Errorf("invalid force in redeem action")
		}

		amount, ok := action["amount"].(float64)
		if !ok {
			return fmt.Errorf("invalid amount in redeem action")
		}

		address, ok := action["address"].(string)
		if !ok {
			return fmt.Errorf("invalid address in redeem action")
		}

		computeExpiration, ok := action["compute_expiration"].(bool)
		if !ok {
			computeExpiration = false
		}
		return executeRedeem(ctx, clientURL, force, amount, address, computeExpiration)
	case "Stats":
		return executeStats(ctx, clientURL)
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

func executeOnboard(ctx context.Context, clientURL string, amount float64) error {
	payload := map[string]float64{"amount": amount}
	_, err := sendRequest(ctx, clientURL+"/onboard", http.MethodPost, payload)
	return err
}

func executeSendAsync(ctx context.Context, clientURL string, amount int64, toAddress string) error {
	payload := map[string]interface{}{
		"amount":     amount,
		"to_address": toAddress,
	}
	_, err := sendRequest(ctx, clientURL+"/sendAsync", http.MethodPost, payload)
	return err
}

func executeClaim(ctx context.Context, clientURL string) error {
	_, err := sendRequest(ctx, clientURL+"/claim", http.MethodPost, nil)
	return err
}

func executeRedeem(ctx context.Context, clientURL string, force bool, amount float64, address string, computeExpiration bool) error {
	payload := map[string]interface{}{
		"force":              force,
		"address":            address,
		"amount":             amount,
		"compute_expiration": computeExpiration,
	}
	_, err := sendRequest(ctx, clientURL+"/redeem", http.MethodPost, payload)
	return err
}

func executeBalance(ctx context.Context, clientURL string) error {
	resp, err := sendRequest(ctx, clientURL+"/balance", http.MethodGet, nil)
	if err != nil {
		return err
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, []byte(resp), "", "  ")
	if err != nil {
		log.Warnf("Failed to format JSON: %v", err)
		sendToFrontend(fmt.Sprintf("Client stats: %s", resp))
	} else {
		resp = prettyJSON.String()
		sendToFrontend(fmt.Sprintf("Client balance:\n%s", prettyJSON.String()))
	}
	log.Infoln("Received balance from client:", resp)

	return nil
}

func executeStats(ctx context.Context, clientURL string) error {
	resp, err := sendRequest(ctx, clientURL+"/stats", http.MethodGet, nil)
	if err != nil {
		return err
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, []byte(resp), "", "  ")
	if err != nil {
		log.Warnf("Failed to format JSON: %v", err)
		sendToFrontend(fmt.Sprintf("Client stats: %s", resp))
	} else {
		resp = prettyJSON.String()
		sendToFrontend(fmt.Sprintf("Client stats:\n%s", prettyJSON.String()))
	}
	log.Infoln("Received stats from client:", resp)

	return nil
}

func sendRequest(ctx context.Context, urlStr string, method string, payload interface{}) (string, error) {
	var req *http.Request
	var err error

	if method == http.MethodGet && payload != nil {
		params, ok := payload.(map[string]string)
		if !ok {
			return "", fmt.Errorf("payload must be of type map[string]string for GET requests")
		}

		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			return "", fmt.Errorf("invalid URL: %w", err)
		}

		query := parsedURL.Query()
		for key, value := range params {
			query.Set(key, value)
		}
		parsedURL.RawQuery = query.Encode()

		req, err = http.NewRequestWithContext(ctx, method, parsedURL.String(), nil)
		if err != nil {
			return "", fmt.Errorf("failed to create GET request: %w", err)
		}
	} else {
		var body io.Reader

		if payload != nil {
			jsonData, err := json.Marshal(payload)
			if err != nil {
				return "", fmt.Errorf("failed to marshal payload to JSON: %w", err)
			}
			body = bytes.NewBuffer(jsonData)
		}

		req, err = http.NewRequestWithContext(ctx, method, urlStr, body)
		if err != nil {
			return "", fmt.Errorf("failed to create %s request: %w", method, err)
		}

		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("request to %s timed out", urlStr)
		}
		return "", fmt.Errorf("request to %s failed: %w", urlStr, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return string(bodyBytes), nil
}

func checkECSQuotas(ctx context.Context, requestedClients int) error {
	awsRegion := "eu-central-1"
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(awsRegion),
	)
	if err != nil {
		return fmt.Errorf("unable to load AWS SDK config: %v", err)
	}
	sqClient := servicequotas.NewFromConfig(cfg)

	quotaCode := "L-3032A538"
	serviceCode := "fargate"

	output, err := sqClient.GetServiceQuota(ctx, &servicequotas.GetServiceQuotaInput{
		ServiceCode: &serviceCode,
		QuotaCode:   &quotaCode,
	})
	if err != nil {
		var rnf *servicequotasTypes.NoSuchResourceException
		if errors.As(err, &rnf) {
			return fmt.Errorf("could not find the fargate quota for tasks: %v", err)
		}
		return fmt.Errorf("failed to get fargate service quota: %v", err)
	}

	if output.Quota == nil || output.Quota.Value == nil {
		return fmt.Errorf("unable to determine fargate task limit from quotas")
	}

	maxTasks := *output.Quota.Value
	if float64(requestedClients) > maxTasks {
		return fmt.Errorf("you requested %d clients, but the fargate quota allows only %.0f concurrent tasks", requestedClients, maxTasks)
	}

	return nil
}

// TODO
// remove remote folder, leave only local client per process, refactor readme, refactor ec2 starting script maybe
// check how to implement more containers per ecs task
// improve SDK profiling
// check session
