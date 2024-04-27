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
	WalletAddr            string
	RoundInterval         int64
	Port                  uint32
	DbType                string
	DbDir                 string
	SchedulerType         string
	TxBuilderType         string
	BlockchainScannerType string
	NoTLS                 bool
	Network               common.Network
	LogLevel              int
	MinRelayFee           uint64
	RoundLifetime         int64
	UnilateralExitDelay   int64
}

var (
	Datadir               = "DATADIR"
	WalletAddr            = "WALLET_ADDR"
	RoundInterval         = "ROUND_INTERVAL"
	Port                  = "PORT"
	DbType                = "DB_TYPE"
	SchedulerType         = "SCHEDULER_TYPE"
	TxBuilderType         = "TX_BUILDER_TYPE"
	BlockchainScannerType = "BC_SCANNER_TYPE"
	Insecure              = "INSECURE"
	LogLevel              = "LOG_LEVEL"
	Network               = "NETWORK"
	MinRelayFee           = "MIN_RELAY_FEE"
	RoundLifetime         = "ROUND_LIFETIME"
	UnilateralExitDelay   = "UNILATERAL_EXIT_DELAY"

	defaultDatadir               = common.AppDataDir("arkd", false)
	defaultRoundInterval         = 5
	defaultPort                  = 6000
	defaultWalletAddr            = "localhost:18000"
	defaultDbType                = "badger"
	defaultSchedulerType         = "gocron"
	defaultTxBuilderType         = "covenant"
	defaultBlockchainScannerType = "ocean"
	defaultInsecure              = true
	defaultNetwork               = "liquid"
	defaultLogLevel              = 4
	defaultMinRelayFee           = 30     // 0.1 sat/vbyte on Liquid
	defaultRoundLifetime         = 604800 // 1 week
	defaultUnilateralExitDelay   = 1440   // 1 day
)

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("ARK")
	viper.AutomaticEnv()

	viper.SetDefault(Datadir, defaultDatadir)
	viper.SetDefault(Port, defaultPort)
	viper.SetDefault(DbType, defaultDbType)
	viper.SetDefault(Insecure, defaultInsecure)
	viper.SetDefault(LogLevel, defaultLogLevel)
	viper.SetDefault(Network, defaultNetwork)
	viper.SetDefault(WalletAddr, defaultWalletAddr)
	viper.SetDefault(MinRelayFee, defaultMinRelayFee)
	viper.SetDefault(RoundInterval, defaultRoundInterval)
	viper.SetDefault(RoundLifetime, defaultRoundLifetime)
	viper.SetDefault(SchedulerType, defaultSchedulerType)
	viper.SetDefault(TxBuilderType, defaultTxBuilderType)
	viper.SetDefault(UnilateralExitDelay, defaultUnilateralExitDelay)
	viper.SetDefault(BlockchainScannerType, defaultBlockchainScannerType)

	net, err := getNetwork()
	if err != nil {
		return nil, err
	}

	if err := initDatadir(); err != nil {
		return nil, fmt.Errorf("error while creating datadir: %s", err)
	}

	return &Config{
		WalletAddr:            viper.GetString(WalletAddr),
		RoundInterval:         viper.GetInt64(RoundInterval),
		Port:                  viper.GetUint32(Port),
		DbType:                viper.GetString(DbType),
		SchedulerType:         viper.GetString(SchedulerType),
		TxBuilderType:         viper.GetString(TxBuilderType),
		BlockchainScannerType: viper.GetString(BlockchainScannerType),
		NoTLS:                 viper.GetBool(Insecure),
		DbDir:                 filepath.Join(viper.GetString(Datadir), "db"),
		LogLevel:              viper.GetInt(LogLevel),
		Network:               net,
		MinRelayFee:           viper.GetUint64(MinRelayFee),
		RoundLifetime:         viper.GetInt64(RoundLifetime),
		UnilateralExitDelay:   viper.GetInt64(UnilateralExitDelay),
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
	case "liquid":
		return common.Liquid, nil
	case "testnet":
		return common.TestNet, nil
	case "regtest":
		return common.RegTest, nil
	default:
		return common.Network{}, fmt.Errorf("unknown network %s", viper.GetString(Network))
	}
}
