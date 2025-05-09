package config

import (
	"fmt"
	"github.com/ark-network/ark/common"
	application "github.com/ark-network/ark/server/pkg/btc-wallet/internal/core"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
	"strings"
)

var (
	Port         = "PORT"
	Datadir      = "DATADIR"
	LogLevel     = "LOG_LEVEL"
	Network      = "NETWORK"
	EsploraURL   = "ESPLORA_URL"
	NeutrinoPeer = "NEUTRINO_PEER"
	// #nosec G101
	BitcoindRpcUser = "BITCOIND_RPC_USER"
	// #nosec G101
	BitcoindRpcPass  = "BITCOIND_RPC_PASS"
	BitcoindRpcHost  = "BITCOIND_RPC_HOST"
	BitcoindZMQBlock = "BITCOIND_ZMQ_BLOCK"
	BitcoindZMQTx    = "BITCOIND_ZMQ_TX"

	defaultPort       = 6060
	defaultLogLevel   = int(log.InfoLevel)
	defaultDatadir    = common.AppDataDir("ark-btc-wallet", false)
	defaultNetwork    = "bitcoin"
	defaultEsploraURL = "https://blockstream.info/api"
)

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("ARK_BTC_WALLET")
	viper.AutomaticEnv()

	viper.SetDefault(Port, defaultPort)
	viper.SetDefault(Datadir, defaultDatadir)
	viper.SetDefault(LogLevel, defaultLogLevel)
	viper.SetDefault(Network, defaultNetwork)
	viper.SetDefault(EsploraURL, defaultEsploraURL)

	net, err := getNetwork()
	if err != nil {
		return nil, fmt.Errorf("error while getting network: %s", err)
	}

	if err := initDatadir(); err != nil {
		return nil, fmt.Errorf("error while creating datadir: %s", err)
	}

	dbPath := filepath.Join(viper.GetString(Datadir), "db")
	if err := makeDirectoryIfNotExists(dbPath); err != nil {
		return nil, fmt.Errorf("failed to create db dir: %s", err)
	}

	cfg := &Config{
		Port:             viper.GetUint32(Port),
		DbDir:            dbPath,
		LogLevel:         viper.GetInt(LogLevel),
		Network:          net,
		EsploraURL:       viper.GetString(EsploraURL),
		NeutrinoPeer:     viper.GetString(NeutrinoPeer),
		BitcoindRpcUser:  viper.GetString(BitcoindRpcUser),
		BitcoindRpcPass:  viper.GetString(BitcoindRpcPass),
		BitcoindRpcHost:  viper.GetString(BitcoindRpcHost),
		BitcoindZMQBlock: viper.GetString(BitcoindZMQBlock),
		BitcoindZMQTx:    viper.GetString(BitcoindZMQTx),
	}

	if err := cfg.walletService(); err != nil {
		return nil, fmt.Errorf("error while creating wallet service: %s", err)
	}

	return cfg, nil
}

type Config struct {
	Port             uint32
	DbDir            string
	LogLevel         int
	Network          common.Network
	EsploraURL       string
	NeutrinoPeer     string
	BitcoindRpcUser  string
	BitcoindRpcPass  string
	BitcoindRpcHost  string
	BitcoindZMQBlock string
	BitcoindZMQTx    string

	WalletSvc application.WalletService
}

func (c *Config) walletService() error {
	// Check if both Neutrino peer and Bitcoind RPC credentials are provided
	if c.NeutrinoPeer != "" && (c.BitcoindRpcUser != "" || c.BitcoindRpcPass != "") {
		return fmt.Errorf("cannot use both Neutrino peer and Bitcoind RPC credentials")
	}

	var svc application.WalletService
	var err error

	switch {
	case c.BitcoindZMQBlock != "" && c.BitcoindZMQTx != "" && c.BitcoindRpcUser != "" && c.BitcoindRpcPass != "":
		svc, err = application.NewService(application.WalletConfig{
			Datadir: c.DbDir,
			Network: c.Network,
		}, application.WithBitcoindZMQ(c.BitcoindZMQBlock, c.BitcoindZMQTx, c.BitcoindRpcHost, c.BitcoindRpcUser, c.BitcoindRpcPass))
	case c.BitcoindRpcUser != "" && c.BitcoindRpcPass != "":
		svc, err = application.NewService(application.WalletConfig{
			Datadir: c.DbDir,
			Network: c.Network,
		}, application.WithPollingBitcoind(c.BitcoindRpcHost, c.BitcoindRpcUser, c.BitcoindRpcPass))
	default:
		// Default to Neutrino for Bitcoin mainnet or when NeutrinoPeer is explicitly set
		if len(c.EsploraURL) == 0 {
			return fmt.Errorf("missing esplora url, covenant-less ark requires ARK_ESPLORA_URL to be set")
		}
		svc, err = application.NewService(application.WalletConfig{
			Datadir: c.DbDir,
			Network: c.Network,
		}, application.WithNeutrino(c.NeutrinoPeer, c.EsploraURL))
	}
	if err != nil {
		return err
	}

	c.WalletSvc = svc
	return nil
}

func initDatadir() error {
	datadir := viper.GetString(Datadir)
	return makeDirectoryIfNotExists(datadir)
}

func makeDirectoryIfNotExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, os.ModeDir|0755)
	}
	return nil
}

func getNetwork() (common.Network, error) {
	switch strings.ToLower(viper.GetString(Network)) {
	case common.Bitcoin.Name:
		return common.Bitcoin, nil
	case common.BitcoinTestNet.Name:
		return common.BitcoinTestNet, nil
	case common.BitcoinTestNet4.Name:
		return common.BitcoinTestNet4, nil
	case common.BitcoinSigNet.Name:
		return common.BitcoinSigNet, nil
	case common.BitcoinMutinyNet.Name:
		return common.BitcoinMutinyNet, nil
	case common.BitcoinRegTest.Name:
		return common.BitcoinRegTest, nil
	default:
		return common.Network{}, fmt.Errorf("unknown network %s", viper.GetString(Network))
	}
}
