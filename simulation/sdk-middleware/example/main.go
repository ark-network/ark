package main

import (
	"context"
	arksdk "github.com/ark-network/ark/pkg/client-sdk"
	"os"
	"path/filepath"

	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	middleware "github.com/ark-network/ark/simulation/sdk-middleware"
	"github.com/sirupsen/logrus"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	profileDir := "./profiles"
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		logger.Fatal(err)
	}

	storeSvc, err := store.NewStore(store.Config{
		ConfigStoreType: types.InMemoryStore,
	})
	if err != nil {
		logger.Fatal(err)
	}

	originalClient, err := arksdk.NewCovenantlessClient(storeSvc)
	if err != nil {
		logger.Fatal(err)
	}

	// Initialize StatsCollectors
	inMemoryStatsCollector := middleware.NewInMemoryStatsCollector()
	loggingStatsCollector := middleware.NewLoggingStatsCollector()

	// Create CompositeStatsCollector
	compositeStatsCollector := middleware.NewCompositeStatsCollector(
		loggingStatsCollector,
		inMemoryStatsCollector,
	)

	// Initialize middleware chain with StatsCollectors
	chain := middleware.NewChain()

	// Middlewares using compositeStatsCollector (both logging and in-memory)
	chain.Add(middleware.NewCPUProfileMiddleware(compositeStatsCollector, profileDir))
	chain.Add(middleware.NewCPUUtilizationMiddleware(compositeStatsCollector))

	// Middlewares using loggingStatsCollector only
	chain.Add(middleware.NewMemoryProfileMiddleware(loggingStatsCollector, profileDir))
	chain.Add(middleware.NewMemoryStatsMiddleware(loggingStatsCollector))

	client := middleware.NewArkClientProxy(originalClient, chain)

	ctx := context.Background()

	err = client.Init(ctx, arksdk.InitArgs{
		WalletType:          arksdk.SingleKeyWallet,
		ClientType:          arksdk.GrpcClient,
		ServerUrl:           "localhost:7070",
		Password:            "password",
		WithTransactionFeed: true,
	})
	if err != nil {
		logger.Fatal(err)
	}

	balance, err := client.Balance(ctx, true)
	if err != nil {
		logger.Fatal(err)
	}

	logger.Infof("Balance: %+v", balance)

	files, err := filepath.Glob(filepath.Join(profileDir, "*.prof"))
	if err != nil {
		logger.Fatal(err)
	}
	logger.Info("Profile files created:", files)
	logger.Info("To analyze CPU profiles: go tool pprof <cpu_profile_file>")
	logger.Info("To analyze heap profiles: go tool pprof <heap_profile_file>")
	logger.Info("Real-time metrics have been logged during execution")
}
