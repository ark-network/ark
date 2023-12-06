package config

import (
	"fmt"
	"os"

	common "github.com/ark-network/ark/common"
	"github.com/spf13/viper"
)

type Config struct {
	WalletAddr    string
	RoundInterval int64
	Network       common.Network
	BaseDirectory string
}

var (
	Datadir       = "DATADIR"
	WalletAddr    = "WALLET_ADDR"
	RoundInterval = "ROUND_INTERVAL"
	Network       = "NETWORK"

	defaultDatadir       = common.AppDataDir("arkd", false)
	defaultRoundInterval = 60
)

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("ARK")
	viper.AutomaticEnv()

	viper.SetDefault(Datadir, defaultDatadir)
	viper.SetDefault(RoundInterval, defaultRoundInterval)
	viper.SetDefault(Network, "mainnet")

	if err := initDatadir(); err != nil {
		return nil, fmt.Errorf("error while creating datadir: %s", err)
	}

	net, err := networkFromString(viper.GetString(Network))
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		WalletAddr:    viper.GetString(WalletAddr),
		RoundInterval: viper.GetInt64(RoundInterval),
		Network:       *net,
		BaseDirectory: viper.GetString(Datadir),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if len(c.WalletAddr) <= 0 {
		return fmt.Errorf("missing wallet address")
	}
	if c.RoundInterval < 5 {
		return fmt.Errorf("round interval must be at least 5 seconds")
	}
	return nil
}

func networkFromString(network string) (*common.Network, error) {
	switch network {
	case common.MainNet.Name:
		return &common.MainNet, nil
	case common.TestNet.Name:
		return &common.TestNet, nil
	default:
		return nil, fmt.Errorf("invalid network: %s", network)
	}
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
