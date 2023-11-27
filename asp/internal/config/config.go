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
}

var (
	Datadir       = "DATADIR"
	WalletAddr    = "WALLET_ADDR"
	RoundInterval = "ROUND_INTERVAL"

	defaultDatadir       = common.AppDataDir("arkd", false)
	defaultRoundInterval = 60
)

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("ARK")
	viper.AutomaticEnv()

	viper.SetDefault(Datadir, defaultDatadir)
	viper.SetDefault(RoundInterval, defaultRoundInterval)

	if err := initDatadir(); err != nil {
		return nil, fmt.Errorf("error while creating datadir: %s", err)
	}

	cfg := &Config{
		WalletAddr:    viper.GetString(WalletAddr),
		RoundInterval: viper.GetInt64(RoundInterval),
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
