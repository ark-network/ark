package main

import (
	"os"
	"os/signal"
	"syscall"

	appconfig "github.com/ark-network/ark/internal/app-config"
	"github.com/ark-network/ark/internal/config"
	grpcservice "github.com/ark-network/ark/internal/interface/grpc"
	log "github.com/sirupsen/logrus"
)

//nolint:all
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.WithError(err).Fatal("invalid config")
	}

	log.SetLevel(log.Level(cfg.LogLevel))

	svcConfig := grpcservice.Config{
		Port:  cfg.Port,
		NoTLS: cfg.NoTLS,
	}

	if cfg.RoundLifetime%512 != 0 {
		setLifetime := cfg.RoundLifetime
		cfg.RoundLifetime = cfg.RoundLifetime - (cfg.RoundLifetime % 512)
		log.Infof("round lifetime must be a multiple of 512, %d -> %d", setLifetime, cfg.RoundLifetime)
	}

	if cfg.ExitDelay%512 != 0 {
		setExitDelay := cfg.ExitDelay
		cfg.ExitDelay = cfg.ExitDelay - (cfg.ExitDelay % 512)
		log.Infof("exit delay must be a multiple of 512, %d -> %d", setExitDelay, cfg.ExitDelay)
	}

	appConfig := &appconfig.Config{
		DbType:                cfg.DbType,
		DbDir:                 cfg.DbDir,
		RoundInterval:         cfg.RoundInterval,
		Network:               cfg.Network,
		SchedulerType:         cfg.SchedulerType,
		TxBuilderType:         cfg.TxBuilderType,
		BlockchainScannerType: cfg.BlockchainScannerType,
		WalletAddr:            cfg.WalletAddr,
		MinRelayFee:           cfg.MinRelayFee,
		RoundLifetime:         cfg.RoundLifetime,
		ExitDelay:             cfg.ExitDelay,
	}
	svc, err := grpcservice.NewService(svcConfig, appConfig)
	if err != nil {
		log.Fatal(err)
	}

	log.RegisterExitHandler(svc.Stop)

	log.Info("starting service...")
	if err := svc.Start(); err != nil {
		log.Fatal(err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	<-sigChan

	log.Info("shutting down service...")
	log.Exit(0)
}
