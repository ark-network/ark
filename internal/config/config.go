package config

import (
	"fmt"
	"os"

	common "github.com/ark-network/ark/common"
	"github.com/spf13/viper"
)

type Config struct {
	WalletAddr string
}

var (
	Datadir    = "DATADIR"
	WalletAddr = "WALLET_ADDR"

	defaultDatadir = common.AppDataDir("coordinatord", false)
)

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("ARK_COORDINATOR")
	viper.AutomaticEnv()

	viper.SetDefault(Datadir, defaultDatadir)

	if err := initDatadir(); err != nil {
		return nil, fmt.Errorf("error while creating datadir: %s", err)
	}

	cfg := &Config{
		WalletAddr: viper.GetString(WalletAddr),
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
