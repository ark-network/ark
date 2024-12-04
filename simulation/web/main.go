package main

import (
	"bufio"
	"embed"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	log "github.com/sirupsen/logrus"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

//go:embed templates/*
var content embed.FS

var (
	templates *template.Template
)

const (
	username = "arkadmin"
	password = "arkadmin123"
)

// Initialize a new session store
var store = sessions.NewCookieStore([]byte("your-secret-key"))

type PageData struct {
	SimulationFiles []string
	ErrorMessage    string
}

func init() {
	// Parse templates
	var err error
	templates, err = template.ParseFS(content, "templates/*.html")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	r := mux.NewRouter()

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		// Secure: true, // Uncomment this if using HTTPS
	}

	// Add logging middleware
	r.Use(loggingMiddleware)

	// Routes
	r.HandleFunc("/login", handleLogin).Methods("GET", "POST")
	r.HandleFunc("/logout", handleLogout).Methods("GET")
	r.HandleFunc("/", authMiddleware(handleIndex)).Methods("GET")
	r.HandleFunc("/run", authMiddleware(handleRun)).Methods("GET", "POST")
	r.HandleFunc("/upload", authMiddleware(handleUpload)).Methods("POST")
	r.HandleFunc("/simulation.yaml", authMiddleware(handleSimulationYaml)).Methods("GET")

	port := "8080"
	log.Infof("Starting server on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// Middleware to check if user is authenticated
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "auth-session")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// Handle user login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Render login template
		if err := templates.ExecuteTemplate(w, "login.html", nil); err != nil {
			log.Errorf("Error rendering login template: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Handle POST request
	err := r.ParseForm()
	if err != nil {
		log.Errorf("Error parsing form: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	user := r.FormValue("username")
	pass := r.FormValue("password")

	// Use standard string comparison
	if user == username && pass == password {
		session, _ := store.Get(r, "auth-session")
		session.Values["authenticated"] = true
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	} else {
		// Invalid credentials
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

// Handle user logout
func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")
	session.Values["authenticated"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// Logging middleware
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Log request details
		log.Infof("Request: %s %s", r.Method, r.URL.Path)
		if r.URL.RawQuery != "" {
			log.Infof("Query Params: %s", r.URL.RawQuery)
		}

		// Log form values if present
		if err := r.ParseForm(); err == nil && len(r.Form) > 0 {
			log.Infof("Form Data: %v", r.Form)
		}

		next.ServeHTTP(w, r)

		// Log request duration
		duration := time.Since(start)
		log.Infof("Completed %s %s in %v", r.Method, r.URL.Path, duration)
	})
}

// Get list of simulation files
func getSimulationFiles() ([]string, error) {
	files, err := os.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("error reading simulation directory: %v", err)
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

// Handle index page
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

// Handle simulation run
func handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Redirect to GET request for SSE
		http.Redirect(w, r, "/run?"+r.Form.Encode(), http.StatusSeeOther)
		return
	}

	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Create a channel for cleanup on client disconnect
	done := make(chan bool)
	defer close(done)

	// Create a flusher for SSE
	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Errorf("Streaming not supported")
		fmt.Fprintf(w, "event: error\ndata: Streaming not supported\n\n")
		return
	}

	// Start ping ticker
	pingTicker := time.NewTicker(2 * time.Second)
	defer pingTicker.Stop()

	// Handle client disconnect
	go func() {
		select {
		case <-r.Context().Done():
			log.Infof("Request context done")
			done <- true
		}
	}()

	// Parse query parameters
	err := r.ParseForm()
	if err != nil {
		log.Errorf("Error parsing form: %v", err)
		fmt.Fprintf(w, "event: error\ndata: Failed to parse form\n\n")
		flusher.Flush()
		return
	}

	network := r.Form.Get("network")
	subnetIDs := r.Form.Get("subnet_ids")
	securityGroupIDs := r.Form.Get("security_group_ids")
	aspURL := r.Form.Get("asp_url")
	simFile := r.Form.Get("simulation_file")

	if subnetIDs == "" || securityGroupIDs == "" {
		log.Errorf("Missing required parameters")
		fmt.Fprintf(w, "event: error\ndata: Subnet IDs and Security Group IDs are required\n\n")
		flusher.Flush()
		return
	}

	if network == "signet" && aspURL == "" {
		log.Errorf("Missing ASP URL for signet network")
		fmt.Fprintf(w, "event: error\ndata: ASP URL is required for signet network\n\n")
		flusher.Flush()
		return
	}

	// Set up environment variables
	env := []string{
		fmt.Sprintf("SUBNET_IDS=%s", subnetIDs),
		fmt.Sprintf("SECURITY_GROUP_IDS=%s", securityGroupIDs),
	}

	// Prepare command arguments
	makeArgs := []string{"run-remote"}

	if network == "signet" {
		if aspURL != "" {
			env = append(env, fmt.Sprintf("ASP_URL=%s", aspURL))
		}
		env = append(env, "SIGNET=true")
	}

	if simFile != "" {
		env = append(env, fmt.Sprintf("SIM=%s", simFile))
	}

	env = append(env, "SCHEMA=schema.yaml")
	env = append(env, "COMPOSE=./../docker-compose.clark.regtest.yml")

	log.Infof("Running make command with args: %v", makeArgs)
	log.Infof("Environment variables: %v", env)

	// Send initial message
	fmt.Fprintf(w, "event: message\ndata: Starting simulation on %s network...\n\n", network)
	flusher.Flush()

	// Create and configure command
	cmd := exec.Command("make", makeArgs...)
	cmd.Env = append(os.Environ(), env...)

	// Create pipes for stdout and stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Errorf("Error creating stdout pipe: %v", err)
		fmt.Fprintf(w, "event: error\ndata: Failed to create output pipe\n\n")
		flusher.Flush()
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Errorf("Error creating stderr pipe: %v", err)
		fmt.Fprintf(w, "event: error\ndata: Failed to create error pipe\n\n")
		flusher.Flush()
		return
	}

	// Start command
	if err := cmd.Start(); err != nil {
		log.Errorf("Error starting command: %v", err)
		fmt.Fprintf(w, "event: error\ndata: Failed to start simulation\n\n")
		flusher.Flush()
		return
	}

	// Create a channel for the command completion
	cmdDone := make(chan error)
	go func() {
		cmdDone <- cmd.Wait()
	}()

	// Create scanner for output
	scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
	outputChan := make(chan string)

	// Start scanning in a separate goroutine
	go func() {
		for scanner.Scan() {
			select {
			case <-done:
				return
			default:
				line := scanner.Text()
				if line != "" {
					outputChan <- line
				}
			}
		}
		close(outputChan)
	}()

	// Main event loop
	for {
		select {
		case <-done:
			// Client disconnected, kill the process
			if err := cmd.Process.Kill(); err != nil {
				log.Errorf("Error killing process: %v", err)
			}
			return

		case line, ok := <-outputChan:
			if !ok {
				// Output channel closed, wait for command to finish
				if err := <-cmdDone; err != nil {
					log.Errorf("Command failed: %v", err)
					fmt.Fprintf(w, "event: error\ndata: Simulation failed: %v\n\n", err)
				} else {
					fmt.Fprintf(w, "event: message\ndata: Simulation completed successfully\n\n")
				}
				flusher.Flush()
				return
			}
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", line)
			flusher.Flush()

		case <-pingTicker.C:
			// Send ping event
			if _, err := fmt.Fprintf(w, "event: ping\ndata: ping\n\n"); err != nil {
				log.Errorf("Error sending ping: %v", err)
				return
			}
			flusher.Flush()

		case err := <-cmdDone:
			if err != nil {
				log.Errorf("Command failed: %v", err)
				fmt.Fprintf(w, "event: error\ndata: Simulation failed: %v\n\n", err)
			} else {
				fmt.Fprintf(w, "event: message\ndata: Simulation completed successfully\n\n")
			}
			flusher.Flush()
			return
		}
	}
}

// Handle file upload
func handleUpload(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("simulation")
	if err != nil {
		log.Errorf("Error getting uploaded file: %v", err)
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file extension
	if !strings.HasSuffix(header.Filename, ".yaml") && !strings.HasSuffix(header.Filename, ".yml") {
		log.Errorf("Invalid file type: %s", header.Filename)
		http.Error(w, "Only YAML files (.yaml, .yml) are allowed", http.StatusBadRequest)
		return
	}

	log.Infof("Received file upload: %s", header.Filename)

	// Save file to simulation directory
	dst, err := os.Create(header.Filename)
	if err != nil {
		log.Errorf("Error creating file: %v", err)
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy uploaded file
	if _, err := io.Copy(dst, file); err != nil {
		log.Errorf("Error saving file: %v", err)
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	log.Infof("File uploaded successfully: %s", header.Filename)

	// Get updated list of simulation files
	simFiles, err := getSimulationFiles()
	if err != nil {
		log.Errorf("Error getting simulation files after upload: %v", err)
		http.Error(w, "Failed to update simulation list", http.StatusInternalServerError)
		return
	}

	// Return HTML for the simulation files dropdown with the new file selected
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("HX-Trigger", `{"showMessage": "Simulation file uploaded successfully"}`)

	// Return updated dropdown with the new file selected
	for _, file := range simFiles {
		selected := ""
		if file == header.Filename {
			selected = " selected"
		}
		fmt.Fprintf(w, `<option value="%s"%s>%s</option>`, file, selected, file)
	}
}

// Handle simulation YAML preview
func handleSimulationYaml(w http.ResponseWriter, r *http.Request) {
	yamlType := r.URL.Query().Get("type")
	selectedFile := r.URL.Query().Get("simulation_file")

	var filePath string
	if yamlType == "schema" {
		filePath = "schema.yaml"
	} else if selectedFile != "" {
		filePath = selectedFile
	} else {
		// Default to first simulation file if none selected
		simFiles, err := getSimulationFiles()
		if err != nil || len(simFiles) == 0 {
			http.Error(w, "No simulation files available", http.StatusNotFound)
			return
		}
		filePath = simFiles[0]
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Errorf("Error reading YAML file: %v", err)
		http.Error(w, "Failed to read YAML file", http.StatusInternalServerError)
		return
	}

	// Return the content with syntax highlighting
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<pre><code class="language-yaml">%s</code></pre>
	<script>
		hljs.highlightElement(document.querySelector('#simulation-preview code'));
		// Ensure proper height
		document.querySelector('#simulation-preview').style.height = 'auto';
	</script>`, content)
}
