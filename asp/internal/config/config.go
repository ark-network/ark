package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	common "github.com/ark-network/ark/common"
	"github.com/spf13/viper"
)

type Config struct {
	WalletAddr    string
	RoundInterval int64
	Port          uint32
	DbType        string
	DbDir         string
	SchedulerType string
	TxBuilderType string
	NoTLS         bool
	Network       common.Network
	LogLevel      int
	MinRelayFee   uint64
}

var (
	Datadir       = "DATADIR"
	WalletAddr    = "WALLET_ADDR"
	RoundInterval = "ROUND_INTERVAL"
	Port          = "PORT"
	DbType        = "DB_TYPE"
	SchedulerType = "SCHEDULER_TYPE"
	TxBuilderType = "TX_BUILDER_TYPE"
	Insecure      = "INSECURE"
	LogLevel      = "LOG_LEVEL"
	Network       = "NETWORK"
	MinRelayFee   = "MIN_RELAY_FEE"

	defaultDatadir       = common.AppDataDir("arkd", false)
	defaultRoundInterval = 60
	defaultPort          = 6000
	defaultDbType        = "badger"
	defaultSchedulerType = "gocron"
	defaultTxBuilderType = "covenant"
	defaultInsecure      = true
	defaultNetwork       = "testnet"
	defaultLogLevel      = 5
	defaultMinRelayFee   = 30
)

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("ARK")
	viper.AutomaticEnv()

	viper.SetDefault(Datadir, defaultDatadir)
	viper.SetDefault(RoundInterval, defaultRoundInterval)
	viper.SetDefault(Port, defaultPort)
	viper.SetDefault(DbType, defaultDbType)
	viper.SetDefault(SchedulerType, defaultSchedulerType)
	viper.SetDefault(TxBuilderType, defaultTxBuilderType)
	viper.SetDefault(Insecure, defaultInsecure)
	viper.SetDefault(LogLevel, defaultLogLevel)
	viper.SetDefault(Network, defaultNetwork)
	viper.SetDefault(MinRelayFee, defaultMinRelayFee)

	net, err := getNetwork()
	if err != nil {
		return nil, err
	}

	if err := initDatadir(); err != nil {
		return nil, fmt.Errorf("error while creating datadir: %s", err)
	}

	return &Config{
		WalletAddr:    viper.GetString(WalletAddr),
		RoundInterval: viper.GetInt64(RoundInterval),
		Port:          viper.GetUint32(Port),
		DbType:        viper.GetString(DbType),
		SchedulerType: viper.GetString(SchedulerType),
		TxBuilderType: viper.GetString(TxBuilderType),
		NoTLS:         viper.GetBool(Insecure),
		DbDir:         filepath.Join(viper.GetString(Datadir), "db"),
		LogLevel:      viper.GetInt(LogLevel),
		Network:       net,
		MinRelayFee:   viper.GetUint64(MinRelayFee),
	}, nil
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
	case "mainnet":
		return common.MainNet, nil
	case "testnet":
		return common.TestNet, nil
	default:
		return common.Network{}, fmt.Errorf("unknown network")
	}
}
