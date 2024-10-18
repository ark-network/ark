package main

import (
	"context"
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

	tempDirs      []string
	tempDirsMutex sync.Mutex
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

	roundLifetime := fmt.Sprintf("%d", simulation.Server.RoundInterval)
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
	if _, err := utils.RunCommand("docker", "compose", "-f", composePath, "--env-file", tmpfile.Name(), "up", "-d", "--build"); err != nil {
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
		if err := utils.GenerateBlock(); err != nil {
			log.Fatal(err)
		}

		time.Sleep(5 * time.Second)
	}()

	defer func() {
		tempDirsMutex.Lock()
		defer tempDirsMutex.Unlock()
		for _, dir := range tempDirs {
			if err := os.RemoveAll(dir); err != nil {
				log.Errorf("failed to remove dir: %v", err)
			}
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
			for _, action := range actions {
				wg.Add(1)
				go func(u User, a interface{}) {
					defer wg.Done()
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
				}(user, action)
			}
		}
		wg.Wait()
		time.Sleep(time.Duration(simulation.Server.RoundInterval) * 2 * time.Second)
	}

}

func loadAndValidateSimulation(simFile string) (*Simulation, error) {
	schemaBytes, err := os.ReadFile("schema.yaml")
	if err != nil {
		return nil, fmt.Errorf("error reading schema file: %v", err)
	}

	schemaJSON, err := yaml.YAMLToJSON(schemaBytes)
	if err != nil {
		return nil, fmt.Errorf("error converting schema YAML to JSON: %v", err)
	}

	schemaLoader := gojsonschema.NewBytesLoader(schemaJSON)

	simBytes, err := os.ReadFile(simFile)
	if err != nil {
		return nil, fmt.Errorf("error reading simulation file: %v", err)
	}

	var sim Simulation
	err = yaml.Unmarshal(simBytes, &sim)
	if err != nil {
		return nil, fmt.Errorf("error parsing simulation YAML: %v", err)
	}

	simJSON, err := yaml.YAMLToJSON(simBytes)
	if err != nil {
		return nil, fmt.Errorf("error converting simulation YAML to JSON: %v", err)
	}

	documentLoader := gojsonschema.NewBytesLoader(simJSON)

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

	return &sim, nil
}

func setupArkClient() (arksdk.ArkClient, error) {
	tempDir, err := os.MkdirTemp("", "ark_client_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %s", err)
	}

	// Store the temporary directory path for later cleanup
	tempDirsMutex.Lock()
	tempDirs = append(tempDirs, tempDir)
	tempDirsMutex.Unlock()

	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType:  types.FileStore,
		AppDataStoreType: types.KVStore,
		BaseDir:          tempDir,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create store: %s", err)
	}

	client, err := arksdk.NewCovenantlessClient(appDataStore)
	if err != nil {
		return nil, fmt.Errorf("failed to setup ark client: %s", err)
	}

	if err := client.Init(context.Background(), arksdk.InitArgs{
		WalletType: walletType,
		ClientType: clientType,
		AspUrl:     aspUrl,
		Password:   password,
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize wallet: %s", err)
	}

	return client, nil
}

func onboard(user User, amount float64) error {
	ctx := context.Background()
	if err := user.client.Unlock(ctx, password); err != nil {
		return err
	}
	defer user.client.Lock(ctx, password)

	_, boardingAddress, err := user.client.Receive(ctx)
	if err != nil {
		return err
	}

	amountStr := fmt.Sprintf("%.8f", amount)

	if _, err := utils.RunCommand("nigiri", "faucet", boardingAddress, amountStr); err != nil {
		return err
	}

	time.Sleep(2 * time.Second)

	_, err = user.client.Claim(ctx)
	return err
}

func sendAsync(user User, amount float64, to string, users map[string]User) error {
	ctx := context.Background()
	if err := user.client.Unlock(ctx, password); err != nil {
		return err
	}
	defer user.client.Lock(ctx, password)

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

	_, err = user.client.SendAsync(ctx, false, receivers)
	return err
}

func claim(user User) error {
	ctx := context.Background()
	if err := user.client.Unlock(ctx, password); err != nil {
		return err
	}
	defer user.client.Lock(ctx, password)

	_, err := user.client.Claim(ctx)
	return err
}

type Simulation struct {
	Version string `yaml:"version"`
	Server  struct {
		Network        string  `yaml:"network"`
		RoundInterval  int     `yaml:"round_interval"`
		InitialFunding float64 `yaml:"initial_funding"`
	} `yaml:"server"`
	Clients []struct {
		ID             string  `yaml:"id"`
		Name           string  `yaml:"name"`
		InitialFunding float64 `yaml:"initial_funding,omitempty"`
	} `yaml:"clients"`
	Rounds []struct {
		Number  int                      `yaml:"number"`
		Actions map[string][]interface{} `yaml:"actions"`
	} `yaml:"rounds"`
}

type User struct {
	client         arksdk.ArkClient
	ID             string
	Name           string
	InitialFunding float64
}
