package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"os"
	"sync"
	"time"

	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	utils "github.com/ark-network/ark/server/test/e2e"
	log "github.com/sirupsen/logrus"

	"github.com/xeipuuv/gojsonschema"
	"sigs.k8s.io/yaml"
)

const (
	composePath = "../docker-compose.clark.regtest.yml"
)

var (
	aspUrl     = "localhost:7070"
	clientType = arksdk.GrpcClient
	password   = "password"
	walletType = arksdk.SingleKeyWallet
)

func main() {
	simFile := flag.String("simulation", "simulation1.yaml", "Path to the simulation YAML file")
	flag.Parse()

	simulation, err := loadAndValidateSimulation(*simFile)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Simulation Version: %s\n", simulation.Version)
	log.Infof("ASP Network: %s\n", simulation.Server.Network)
	log.Infof("Number of Clients: %d\n", len(simulation.Clients))
	log.Infof("Number of Rounds: %d\n", len(simulation.Rounds))

	roundLifetime := fmt.Sprintf("ARK_ROUND_INTERVAL=%d", simulation.Server.RoundInterval)
	tmpfile, err := os.CreateTemp("", "docker-env")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write([]byte(roundLifetime)); err != nil {
		log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	log.Infof("Start building ARKD docker container ...")
	if _, err := utils.RunCommand("docker", "compose", "-f", composePath, "--env-file", tmpfile.Name(), "up", "-d"); err != nil {
		log.Fatal(err)
	}

	time.Sleep(10 * time.Second)
	log.Infoln("ASP running...")

	if err := utils.SetupServerWalletCovenantless(simulation.Server.InitialFunding); err != nil {
		log.Fatal(err)
	}

	time.Sleep(3 * time.Second)

	log.Infoln("ASP wallet initialized")

	go func() {
		for {
			if err := utils.GenerateBlock(); err != nil {
				log.Fatal(err)
			}

			time.Sleep(1 * time.Second)
		}
	}()

	users := make(map[string]User)
	usersMtx := sync.Mutex{}
	var wg sync.WaitGroup
	for _, v := range simulation.Clients {
		wg.Add(1)
		go func(id string, initialFunding float64) {
			defer wg.Done()
			cl, err := setupArkClient()
			if err != nil {
				log.Fatal(err)
			}

			usersMtx.Lock()
			users[id] = User{
				client:         cl,
				ID:             id,
				InitialFunding: initialFunding,
			}
			usersMtx.Unlock()
		}(v.ID, v.InitialFunding)
	}
	wg.Wait()
	log.Infof("Client wallets initialized")

	for _, round := range simulation.Rounds {
		log.Infof("Executing Round %d\n", round.Number)
		var wg sync.WaitGroup
		for clientID, actions := range round.Actions {
			user, ok := users[clientID]
			if !ok {
				log.Fatalf("User %s not found", clientID)
			}
			wg.Add(1)
			go func(u User, actions []interface{}) {
				defer wg.Done()
				for _, a := range actions {
					actionMap := a.(map[string]interface{})
					actionType := actionMap["type"].(string)
					amount, _ := actionMap["amount"].(float64)
					to, _ := actionMap["to"].(string)

					var err error
					switch actionType {
					case "Onboard":
						err = onboard(u, amount)
					case "SendAsync":
						err = sendAsync(u, amount, to, users)
					case "Claim":
						err = claim(u)
					default:
						log.Printf("Unknown action type: %s for user %s", actionType, u.ID)
						return
					}

					if err != nil {
						log.Printf("%s failed for user %s: %v", actionType, u.ID, err)
					}
				}
			}(user, actions)
		}
		wg.Wait()

		time.Sleep(2 * time.Second)
	}

	log.Println("Final balances for all clients:")
	for _, user := range users {
		wg.Add(1)
		go func(u User) {
			defer wg.Done()
			ctx := context.Background()
			balance, err := getBalance(u.client, ctx)
			if err != nil {
				log.Errorf("Failed to get balance for user %s: %v", u.ID, err)
			} else {
				if err := printJSON(u.Name, balance); err != nil {
					log.Errorf("Failed to print JSON for user %s: %v", u.ID, err)
				}
			}
		}(user)
	}
	wg.Wait()
}

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

func setupArkClient() (arksdk.ArkClient, error) {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType: types.InMemoryStore,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create store: %s", err)
	}

	client, err := arksdk.NewCovenantlessClient(appDataStore)
	if err != nil {
		return nil, fmt.Errorf("failed to setup ark client: %s", err)
	}

	ctx := context.Background()
	if err := client.Init(ctx, arksdk.InitArgs{
		WalletType: walletType,
		ClientType: clientType,
		AspUrl:     aspUrl,
		Password:   password,
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize wallet: %s", err)
	}

	if err := client.Unlock(ctx, password); err != nil {
		return nil, fmt.Errorf("failed to unlock wallet: %s", err)
	}

	return client, nil
}

func onboard(user User, amount float64) error {
	ctx := context.Background()

	_, boardingAddress, err := user.client.Receive(ctx)
	if err != nil {
		return err
	}

	amountStr := fmt.Sprintf("%.8f", amount)

	if _, err := utils.RunCommand("nigiri", "faucet", boardingAddress, amountStr); err != nil {
		return err
	}

	time.Sleep(5 * time.Second)

	if _, err = user.client.Settle(ctx); err != nil {
		return fmt.Errorf("user %s failed to onboard: %v", user.ID, err)
	}

	log.Infof("%s onboarded successfully with %f BTC", user.ID, amount)

	return nil
}

func sendAsync(user User, amount float64, to string, users map[string]User) error {
	ctx := context.Background()

	toUser, ok := users[to]
	if !ok {
		return fmt.Errorf("recipient user %s not found", to)
	}

	toAddress, _, err := toUser.client.Receive(ctx)
	if err != nil {
		return err
	}

	receivers := []arksdk.Receiver{
		arksdk.NewBitcoinReceiver(toAddress, uint64(amount*1e8)),
	}

	if _, err = user.client.SendAsync(ctx, false, receivers); err != nil {
		return fmt.Errorf("user %s failed to send %f BTC to user %s: %v", user.ID, amount, toUser.ID, err)
	}

	log.Infof("user %s sent %f BTC to user %s", user.ID, amount, toUser.ID)

	return nil
}

func claim(user User) error {
	ctx := context.Background()

	txID, err := user.client.Settle(ctx)
	if err != nil {
		return fmt.Errorf("user %s failed to claim their funds: %v", user.ID, err)
	}

	log.Infof("User %s claimed their funds, txID: %v", user.ID, txID)

	return nil
}

func getBalance(client arksdk.ArkClient, ctx context.Context) (*arksdk.Balance, error) {
	return client.Balance(ctx, false)
}

type Simulation struct {
	Version string `json:"version"`
	Server  struct {
		Network        string  `json:"network"`
		InitialFunding float64 `json:"initial_funding"`
		RoundInterval  int     `json:"round_interval"`
	} `json:"server"`
	Clients []struct {
		ID             string  `json:"id"`
		Name           string  `json:"name"`
		InitialFunding float64 `json:"initial_funding,omitempty"`
	} `json:"clients"`
	Rounds []struct {
		Number  int                      `json:"number"`
		Actions map[string][]interface{} `json:"actions"`
	} `json:"rounds"`
}
type User struct {
	client         arksdk.ArkClient
	ID             string
	Name           string
	InitialFunding float64
}

func printJSON(user string, resp interface{}) error {
	jsonBytes, err := json.MarshalIndent(resp, "", "\t")
	if err != nil {
		return err
	}
	log.Infof("User: %v", user)
	log.Infoln(string(jsonBytes))
	return nil
}
