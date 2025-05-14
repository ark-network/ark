package main

import (
	"github.com/ark-network/ark/pkg/ark-wallet/internal/config"
	grpcservice "github.com/ark-network/ark/pkg/ark-wallet/internal/interface/grpc"
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("invalid config: %s", err)
	}

	log.SetLevel(log.Level(cfg.LogLevel))

	svc, err := grpcservice.NewService(cfg)
	if err != nil {
		log.Fatalf("failed to create service: %s", err)
	}

	log.Infof("Ark Btc Wallet config: %+v", cfg)

	log.Info("starting service...")
	if err := svc.Start(); err != nil {
		log.Fatalf("failed to start service: %s", err)
	}
	log.Infof("Ark Btc Wallet listens on: %v", cfg.Port)

	log.RegisterExitHandler(svc.Stop)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, os.Interrupt)
	<-sigChan

	log.Info("shutting down service...")
	log.Exit(0)
}
