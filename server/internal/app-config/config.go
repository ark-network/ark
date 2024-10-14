package appconfig

import (
	"fmt"
	"strings"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/server/internal/core/application"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/ark-network/ark/server/internal/infrastructure/db"
	blockscheduler "github.com/ark-network/ark/server/internal/infrastructure/scheduler/block"
	timescheduler "github.com/ark-network/ark/server/internal/infrastructure/scheduler/gocron"
	txbuilder "github.com/ark-network/ark/server/internal/infrastructure/tx-builder/covenant"
	cltxbuilder "github.com/ark-network/ark/server/internal/infrastructure/tx-builder/covenantless"
	envunlocker "github.com/ark-network/ark/server/internal/infrastructure/unlocker/env"
	fileunlocker "github.com/ark-network/ark/server/internal/infrastructure/unlocker/file"
	btcwallet "github.com/ark-network/ark/server/internal/infrastructure/wallet/btc-embedded"
	liquidwallet "github.com/ark-network/ark/server/internal/infrastructure/wallet/liquid-standalone"
	log "github.com/sirupsen/logrus"
)

const minAllowedSequence = 512

var (
	supportedEventDbs = supportedType{
		"badger": {},
	}
	supportedDbs = supportedType{
		"badger": {},
		"sqlite": {},
	}
	supportedSchedulers = supportedType{
		"gocron": {},
		"block":  {},
	}
	supportedTxBuilders = supportedType{
		"covenant":     {},
		"covenantless": {},
	}
	supportedScanners = supportedType{
		"ocean":     {},
		"btcwallet": {},
	}
	supportedUnlockers = supportedType{
		"env":  {},
		"file": {},
	}
	supportedNetworks = supportedType{
		common.Bitcoin.Name:        {},
		common.BitcoinTestNet.Name: {},
		common.BitcoinRegTest.Name: {},
		common.BitcoinSigNet.Name:  {},
		common.Liquid.Name:         {},
		common.LiquidTestNet.Name:  {},
		common.LiquidRegTest.Name:  {},
	}
)

type Config struct {
	DbType                string
	EventDbType           string
	DbDir                 string
	DbMigrationPath       string
	EventDbDir            string
	RoundInterval         int64
	Network               common.Network
	SchedulerType         string
	TxBuilderType         string
	BlockchainScannerType string
	WalletAddr            string
	RoundLifetime         int64
	UnilateralExitDelay   int64
	BoardingExitDelay     int64

	EsploraURL      string
	NeutrinoPeer    string
	BitcoindRpcUser string
	BitcoindRpcPass string
	BitcoindRpcHost string

	UnlockerType     string
	UnlockerFilePath string // file unlocker
	UnlockerPassword string // env unlocker

	repo      ports.RepoManager
	svc       application.Service
	adminSvc  application.AdminService
	wallet    ports.WalletService
	txBuilder ports.TxBuilder
	scanner   ports.BlockchainScanner
	scheduler ports.SchedulerService
	unlocker  ports.Unlocker
}

func (c *Config) Validate() error {
	if !supportedEventDbs.supports(c.EventDbType) {
		return fmt.Errorf("event db type not supported, please select one of: %s", supportedEventDbs)
	}
	if !supportedDbs.supports(c.DbType) {
		return fmt.Errorf("db type not supported, please select one of: %s", supportedDbs)
	}
	if !supportedSchedulers.supports(c.SchedulerType) {
		return fmt.Errorf("scheduler type not supported, please select one of: %s", supportedSchedulers)
	}
	if !supportedTxBuilders.supports(c.TxBuilderType) {
		return fmt.Errorf("tx builder type not supported, please select one of: %s", supportedTxBuilders)
	}
	if !supportedScanners.supports(c.BlockchainScannerType) {
		return fmt.Errorf("blockchain scanner type not supported, please select one of: %s", supportedScanners)
	}
	if len(c.UnlockerType) > 0 && !supportedUnlockers.supports(c.UnlockerType) {
		return fmt.Errorf("unlocker type not supported, please select one of: %s", supportedUnlockers)
	}
	if c.RoundInterval < 2 {
		return fmt.Errorf("invalid round interval, must be at least 2 seconds")
	}
	if !supportedNetworks.supports(c.Network.Name) {
		return fmt.Errorf("invalid network, must be one of: %s", supportedNetworks)
	}
	if len(c.WalletAddr) <= 0 {
		return fmt.Errorf("missing onchain wallet address")
	}
	if c.RoundLifetime < minAllowedSequence {
		if c.SchedulerType != "block" {
			return fmt.Errorf("scheduler type must be block if round lifetime is expressed in blocks")
		}
	} else {
		if c.SchedulerType != "gocron" {
			return fmt.Errorf("scheduler type must be gocron if round lifetime is expressed in seconds")
		}

		// round life time must be a multiple of 512 if expressed in seconds
		if c.RoundLifetime%minAllowedSequence != 0 {
			c.RoundLifetime -= c.RoundLifetime % minAllowedSequence
			log.Infof(
				"round lifetime must be a multiple of %d, rounded to %d",
				minAllowedSequence, c.RoundLifetime,
			)
		}
	}

	if c.UnilateralExitDelay < minAllowedSequence {
		return fmt.Errorf(
			"invalid unilateral exit delay, must at least %d", minAllowedSequence,
		)
	}

	if c.BoardingExitDelay < minAllowedSequence {
		return fmt.Errorf(
			"invalid boarding exit delay, must at least %d", minAllowedSequence,
		)
	}

	if c.UnilateralExitDelay%minAllowedSequence != 0 {
		c.UnilateralExitDelay -= c.UnilateralExitDelay % minAllowedSequence
		log.Infof(
			"unilateral exit delay must be a multiple of %d, rounded to %d",
			minAllowedSequence, c.UnilateralExitDelay,
		)
	}

	if c.BoardingExitDelay%minAllowedSequence != 0 {
		c.BoardingExitDelay -= c.BoardingExitDelay % minAllowedSequence
		log.Infof(
			"boarding exit delay must be a multiple of %d, rounded to %d",
			minAllowedSequence, c.BoardingExitDelay,
		)
	}

	if err := c.repoManager(); err != nil {
		return err
	}
	if err := c.walletService(); err != nil {
		return err
	}
	if err := c.txBuilderService(); err != nil {
		return err
	}
	if err := c.scannerService(); err != nil {
		return err
	}
	if err := c.schedulerService(); err != nil {
		return err
	}
	if err := c.adminService(); err != nil {
		return err
	}
	if err := c.unlockerService(); err != nil {
		return err
	}
	return nil
}

func (c *Config) AppService() (application.Service, error) {
	if c.svc == nil {
		if err := c.appService(); err != nil {
			return nil, err
		}
	}
	return c.svc, nil
}

func (c *Config) AdminService() application.AdminService {
	return c.adminSvc
}

func (c *Config) WalletService() ports.WalletService {
	return c.wallet
}

func (c *Config) UnlockerService() ports.Unlocker {
	return c.unlocker
}

func (c *Config) repoManager() error {
	var svc ports.RepoManager
	var err error
	var eventStoreConfig []interface{}
	var dataStoreConfig []interface{}
	logger := log.New()

	switch c.EventDbType {
	case "badger":
		eventStoreConfig = []interface{}{c.EventDbDir, logger}
	default:
		return fmt.Errorf("unknown event db type")
	}

	switch c.DbType {
	case "badger":
		dataStoreConfig = []interface{}{c.DbDir, logger}
	case "sqlite":
		dataStoreConfig = []interface{}{c.DbDir, c.DbMigrationPath}
	default:
		return fmt.Errorf("unknown db type")
	}

	svc, err = db.NewService(db.ServiceConfig{
		EventStoreType: c.EventDbType,
		DataStoreType:  c.DbType,

		EventStoreConfig: eventStoreConfig,
		DataStoreConfig:  dataStoreConfig,
	})
	if err != nil {
		return err
	}

	c.repo = svc
	return nil
}

func (c *Config) walletService() error {
	if common.IsLiquid(c.Network) {
		svc, err := liquidwallet.NewService(c.WalletAddr)
		if err != nil {
			return fmt.Errorf("failed to connect to wallet: %s", err)
		}

		c.wallet = svc
		return nil
	}

	// Check if both Neutrino peer and Bitcoind RPC credentials are provided
	if c.NeutrinoPeer != "" && (c.BitcoindRpcUser != "" || c.BitcoindRpcPass != "") {
		return fmt.Errorf("cannot use both Neutrino peer and Bitcoind RPC credentials")
	}

	var svc ports.WalletService
	var err error

	switch {
	case c.NeutrinoPeer != "":
		if len(c.EsploraURL) == 0 {
			return fmt.Errorf("missing esplora url, covenant-less ark requires ARK_ESPLORA_URL to be set")
		}
		svc, err = btcwallet.NewService(btcwallet.WalletConfig{
			Datadir: c.DbDir,
			Network: c.Network,
		}, btcwallet.WithNeutrino(c.NeutrinoPeer, c.EsploraURL))

	case c.BitcoindRpcUser != "" && c.BitcoindRpcPass != "":
		svc, err = btcwallet.NewService(btcwallet.WalletConfig{
			Datadir: c.DbDir,
			Network: c.Network,
		}, btcwallet.WithPollingBitcoind(c.BitcoindRpcHost, c.BitcoindRpcUser, c.BitcoindRpcPass))

	// Placeholder for future initializers like WithBitcoindZMQ
	default:
		return fmt.Errorf("either Neutrino peer or Bitcoind RPC credentials must be provided")
	}

	if err != nil {
		return err
	}

	c.wallet = svc
	return nil
}

func (c *Config) txBuilderService() error {
	var svc ports.TxBuilder
	var err error
	switch c.TxBuilderType {
	case "covenant":
		svc = txbuilder.NewTxBuilder(
			c.wallet, c.Network, c.RoundLifetime, c.BoardingExitDelay,
		)
	case "covenantless":
		svc = cltxbuilder.NewTxBuilder(
			c.wallet, c.Network, c.RoundLifetime, c.BoardingExitDelay,
		)
	default:
		err = fmt.Errorf("unknown tx builder type")
	}
	if err != nil {
		return err
	}

	c.txBuilder = svc
	return nil
}

func (c *Config) scannerService() error {
	var svc ports.BlockchainScanner
	switch c.BlockchainScannerType {
	default:
		svc = c.wallet
	}

	c.scanner = svc
	return nil
}

func (c *Config) schedulerService() error {
	var svc ports.SchedulerService
	var err error
	switch c.SchedulerType {
	case "gocron":
		svc = timescheduler.NewScheduler()
	case "block":
		svc, err = blockscheduler.NewScheduler(c.EsploraURL)
	default:
		err = fmt.Errorf("unknown scheduler type")
	}
	if err != nil {
		return err
	}

	c.scheduler = svc
	return nil
}

func (c *Config) appService() error {
	if common.IsLiquid(c.Network) {
		svc, err := application.NewCovenantService(
			c.Network, c.RoundInterval, c.RoundLifetime, c.UnilateralExitDelay, c.BoardingExitDelay,
			c.wallet, c.repo, c.txBuilder, c.scanner, c.scheduler,
		)
		if err != nil {
			return err
		}

		c.svc = svc
		return nil
	}

	svc, err := application.NewCovenantlessService(
		c.Network, c.RoundInterval, c.RoundLifetime, c.UnilateralExitDelay, c.BoardingExitDelay,
		c.wallet, c.repo, c.txBuilder, c.scanner, c.scheduler,
	)
	if err != nil {
		return err
	}

	c.svc = svc
	return nil
}

func (c *Config) adminService() error {
	unit := ports.UnixTime
	if c.RoundLifetime < minAllowedSequence {
		unit = ports.BlockHeight
	}

	c.adminSvc = application.NewAdminService(c.wallet, c.repo, c.txBuilder, unit)
	return nil
}

func (c *Config) unlockerService() error {
	if len(c.UnlockerType) <= 0 {
		return nil
	}

	var svc ports.Unlocker
	var err error
	switch c.UnlockerType {
	case "file":
		svc, err = fileunlocker.NewService(c.UnlockerFilePath)
	case "env":
		svc, err = envunlocker.NewService(c.UnlockerPassword)
	default:
		err = fmt.Errorf("unknown unlocker type")
	}
	if err != nil {
		return err
	}
	c.unlocker = svc
	return nil
}

type supportedType map[string]struct{}

func (t supportedType) String() string {
	types := make([]string, 0, len(t))
	for tt := range t {
		types = append(types, tt)
	}
	return strings.Join(types, " | ")
}

func (t supportedType) supports(typeStr string) bool {
	_, ok := t[typeStr]
	return ok
}
