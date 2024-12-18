package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ark-network/ark/common"
	appconfig "github.com/ark-network/ark/server/internal/app-config"
	"github.com/ark-network/ark/server/internal/config"
	grpcservice "github.com/ark-network/ark/server/internal/interface/grpc"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// Version will be set during build time
var Version string

// flags
var (
	urlFlag = &cli.StringFlag{
		Name:  "url",
		Usage: "the url where to reach ark server",
		Value: fmt.Sprintf("http://localhost:%d", config.DefaultPort),
	}
	noMacaroonFlag = &cli.BoolFlag{
		Name:  "no-macaroon",
		Usage: "don't use macaroon auth",
		Value: false,
	}
	macaroonFlag = &cli.StringFlag{
		Name:  "macaroon-path",
		Usage: "the path where to find the admin macaroon file",
		Value: filepath.Join(common.AppDataDir("arkd", false), "macaroons", "admin.macaroon"),
	}
	tlsCertFlag = &cli.StringFlag{
		Name:  "tls-cert-path",
		Usage: "the path where to find the TLS certificate",
		Value: filepath.Join(common.AppDataDir("arkd", false), "tls", "cert.pem"),
	}
)

func mainAction(_ *cli.Context) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("invalid config: %s", err)
	}

	log.SetLevel(log.Level(cfg.LogLevel))

	svcConfig := grpcservice.Config{
		Datadir:         cfg.Datadir,
		Port:            cfg.Port,
		NoTLS:           cfg.NoTLS,
		NoMacaroons:     cfg.NoMacaroons,
		TLSExtraIPs:     cfg.TLSExtraIPs,
		TLSExtraDomains: cfg.TLSExtraDomains,
	}

	lifetimeType, unilateralExitType, boardingExitType := common.LocktimeTypeBlock, common.LocktimeTypeBlock, common.LocktimeTypeBlock
	if cfg.RoundLifetime >= 512 {
		lifetimeType = common.LocktimeTypeSecond
	}
	if cfg.UnilateralExitDelay >= 512 {
		unilateralExitType = common.LocktimeTypeSecond
	}
	if cfg.BoardingExitDelay >= 512 {
		boardingExitType = common.LocktimeTypeSecond
	}

	appConfig := &appconfig.Config{
		EventDbType:             cfg.EventDbType,
		DbType:                  cfg.DbType,
		DbDir:                   cfg.DbDir,
		DbMigrationPath:         cfg.DbMigrationPath,
		EventDbDir:              cfg.DbDir,
		RoundInterval:           cfg.RoundInterval,
		Network:                 cfg.Network,
		SchedulerType:           cfg.SchedulerType,
		TxBuilderType:           cfg.TxBuilderType,
		WalletAddr:              cfg.WalletAddr,
		RoundLifetime:           common.RelativeLocktime{Type: lifetimeType, Value: uint32(cfg.RoundLifetime)},
		UnilateralExitDelay:     common.RelativeLocktime{Type: unilateralExitType, Value: uint32(cfg.UnilateralExitDelay)},
		EsploraURL:              cfg.EsploraURL,
		NeutrinoPeer:            cfg.NeutrinoPeer,
		BitcoindRpcUser:         cfg.BitcoindRpcUser,
		BitcoindRpcPass:         cfg.BitcoindRpcPass,
		BitcoindRpcHost:         cfg.BitcoindRpcHost,
		BitcoindZMQBlock:        cfg.BitcoindZMQBlock,
		BitcoindZMQTx:           cfg.BitcoindZMQTx,
		BoardingExitDelay:       common.RelativeLocktime{Type: boardingExitType, Value: uint32(cfg.BoardingExitDelay)},
		UnlockerType:            cfg.UnlockerType,
		UnlockerFilePath:        cfg.UnlockerFilePath,
		UnlockerPassword:        cfg.UnlockerPassword,
		NostrDefaultRelays:      cfg.NostrDefaultRelays,
		NoteUriPrefix:           cfg.NoteUriPrefix,
		MarketHourStartTime:     cfg.MarketHourStartTime,
		MarketHourEndTime:       cfg.MarketHourEndTime,
		MarketHourPeriod:        cfg.MarketHourPeriod,
		MarketHourRoundInterval: cfg.MarketHourRoundInterval,
	}
	svc, err := grpcservice.NewService(svcConfig, appConfig)
	if err != nil {
		return err
	}

	log.Infof("Ark Server config: %+v", appConfig)

	log.Info("starting service...")
	if err := svc.Start(); err != nil {
		return err
	}

	log.RegisterExitHandler(svc.Stop)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, os.Interrupt)
	<-sigChan

	log.Info("shutting down service...")
	log.Exit(0)

	return nil
}

func main() {
	app := cli.NewApp()
	app.Version = Version
	app.Name = "Arkd CLI"
	app.Usage = "arkd command line interface"
	app.Commands = append(app.Commands, walletCmd)
	app.Action = mainAction
	app.Flags = append(app.Flags, urlFlag, noMacaroonFlag, macaroonFlag, tlsCertFlag)

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
