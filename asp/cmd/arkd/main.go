package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/internal/config"
	"github.com/ark-network/ark/internal/core/application"
	"github.com/ark-network/ark/internal/infrastructure/db"
	oceanwallet "github.com/ark-network/ark/internal/infrastructure/ocean-wallet"
	scheduler "github.com/ark-network/ark/internal/infrastructure/scheduler/gocron"
	txbuilder "github.com/ark-network/ark/internal/infrastructure/tx-builder/dummy"
	service_interface "github.com/ark-network/ark/internal/interface"
	"github.com/dgraph-io/badger/v4"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/network"
)

//nolint:all
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	conf, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	walletSvc, err := oceanwallet.NewService(conf.WalletAddr)
	if err != nil {
		log.Fatal(err)
	}

	var logger badger.Logger = log.New()

	badgerConfig := []interface{}{conf.BaseDirectory, logger}

	repoManager, err := db.NewService(db.ServiceConfig{
		EventStoreType:   "badger",
		RoundStoreType:   "badger",
		VtxoStoreType:    "badger",
		EventStoreConfig: badgerConfig,
		RoundStoreConfig: badgerConfig,
		VtxoStoreConfig:  badgerConfig,
	})
	if err != nil {
		log.Fatal(err)
	}

	aspKey, err := walletSvc.GetPubkey(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	svc := application.NewService(
		conf.RoundInterval,
		conf.Network,
		onChainNetwork(conf.Network),
		walletSvc,
		scheduler.NewScheduler(),
		repoManager,
		txbuilder.NewTxBuilder(aspKey, conf.Network),
	)

	interfaceService, err := service_interface.NewService(service_interface.Options{
		ApplicationService: svc,
		RepositoryManager:  repoManager,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Info("starting service...")
	if err := svc.Start(); err != nil {
		log.Fatal(err)
	}

	log.RegisterExitHandler(interfaceService.Stop)

	log.Info("starting grpc interface service...")
	if err := interfaceService.Start(); err != nil {
		log.Fatal(err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	<-sigChan

	log.Info("shutting down service...")
	log.Exit(0)
}

func onChainNetwork(net common.Network) network.Network {
	switch net {
	case common.MainNet:
		return network.Liquid
	case common.TestNet:
		return network.Testnet
	default:
		return network.Liquid
	}
}
