package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	"github.com/nbd-wtf/go-nostr"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
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
	supportedUnlockers = supportedType{
		"env":  {},
		"file": {},
	}
	supportedNetworks = supportedType{
		common.Bitcoin.Name:          {},
		common.BitcoinTestNet.Name:   {},
		common.BitcoinSigNet.Name:    {},
		common.BitcoinMutinyNet.Name: {},
		common.BitcoinRegTest.Name:   {},
		common.Liquid.Name:           {},
		common.LiquidTestNet.Name:    {},
		common.LiquidRegTest.Name:    {},
	}
)

type Config struct {
	Datadir         string
	Port            uint32
	DbMigrationPath string
	NoTLS           bool
	NoMacaroons     bool
	LogLevel        int
	TLSExtraIPs     []string
	TLSExtraDomains []string

	DbType              string
	EventDbType         string
	DbDir               string
	EventDbDir          string
	RoundInterval       int64
	Network             common.Network
	SchedulerType       string
	TxBuilderType       string
	WalletAddr          string
	VtxoTreeExpiry      common.RelativeLocktime
	UnilateralExitDelay common.RelativeLocktime
	BoardingExitDelay   common.RelativeLocktime
	NostrDefaultRelays  []string
	NoteUriPrefix       string

	MarketHourStartTime     time.Time
	MarketHourEndTime       time.Time
	MarketHourPeriod        time.Duration
	MarketHourRoundInterval time.Duration
	OtelCollectorEndpoint   string

	// TODO remove with transactions version 3
	AllowZeroFees bool

	EsploraURL       string
	NeutrinoPeer     string
	BitcoindRpcUser  string
	BitcoindRpcPass  string
	BitcoindRpcHost  string
	BitcoindZMQBlock string
	BitcoindZMQTx    string

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

var (
	Datadir             = "DATADIR"
	WalletAddr          = "WALLET_ADDR"
	RoundInterval       = "ROUND_INTERVAL"
	Port                = "PORT"
	EventDbType         = "EVENT_DB_TYPE"
	DbType              = "DB_TYPE"
	SchedulerType       = "SCHEDULER_TYPE"
	TxBuilderType       = "TX_BUILDER_TYPE"
	LogLevel            = "LOG_LEVEL"
	Network             = "NETWORK"
	VtxoTreeExpiry      = "VTXO_TREE_EXPIRY"
	UnilateralExitDelay = "UNILATERAL_EXIT_DELAY"
	BoardingExitDelay   = "BOARDING_EXIT_DELAY"
	EsploraURL          = "ESPLORA_URL"
	NeutrinoPeer        = "NEUTRINO_PEER"
	NostrDefaultRelays  = "NOSTR_DEFAULT_RELAYS"
	// #nosec G101
	BitcoindRpcUser = "BITCOIND_RPC_USER"
	// #nosec G101
	BitcoindRpcPass         = "BITCOIND_RPC_PASS"
	BitcoindRpcHost         = "BITCOIND_RPC_HOST"
	BitcoindZMQBlock        = "BITCOIND_ZMQ_BLOCK"
	BitcoindZMQTx           = "BITCOIND_ZMQ_TX"
	NoMacaroons             = "NO_MACAROONS"
	NoTLS                   = "NO_TLS"
	TLSExtraIP              = "TLS_EXTRA_IP"
	TLSExtraDomain          = "TLS_EXTRA_DOMAIN"
	UnlockerType            = "UNLOCKER_TYPE"
	UnlockerFilePath        = "UNLOCKER_FILE_PATH"
	UnlockerPassword        = "UNLOCKER_PASSWORD"
	NoteUriPrefix           = "NOTE_URI_PREFIX"
	MarketHourStartTime     = "MARKET_HOUR_START_TIME"
	MarketHourEndTime       = "MARKET_HOUR_END_TIME"
	MarketHourPeriod        = "MARKET_HOUR_PERIOD"
	MarketHourRoundInterval = "MARKET_HOUR_ROUND_INTERVAL"
	OtelCollectorEndpoint   = "OTEL_COLLECTOR_ENDPOINT"

	AllowZeroFees = "ALLOW_ZERO_FEES"

	defaultDatadir             = common.AppDataDir("arkd", false)
	defaultRoundInterval       = 15
	DefaultPort                = 7070
	defaultDbType              = "sqlite"
	defaultEventDbType         = "badger"
	defaultSchedulerType       = "gocron"
	defaultTxBuilderType       = "covenantless"
	defaultNetwork             = "bitcoin"
	defaultEsploraURL          = "https://blockstream.info/api"
	defaultLogLevel            = 5
	defaultVtxoTreeExpiry      = 604672
	defaultUnilateralExitDelay = 1024
	defaultBoardingExitDelay   = 604672
	defaultNoMacaroons         = false
	defaultNoTLS               = true
	defaultNostrDefaultRelays  = []string{"wss://relay.primal.net", "wss://relay.damus.io"}
	defaultMarketHourStartTime = time.Now()
	defaultMarketHourEndTime   = defaultMarketHourStartTime.Add(time.Duration(defaultRoundInterval) * time.Second)
	defaultMarketHourPeriod    = time.Duration(24) * time.Hour
	defaultMarketHourInterval  = time.Duration(defaultRoundInterval) * time.Second

	defaultAllowZeroFees = false
)

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("ARK")
	viper.AutomaticEnv()

	viper.SetDefault(Datadir, defaultDatadir)
	viper.SetDefault(Port, DefaultPort)
	viper.SetDefault(DbType, defaultDbType)
	viper.SetDefault(NoTLS, defaultNoTLS)
	viper.SetDefault(LogLevel, defaultLogLevel)
	viper.SetDefault(Network, defaultNetwork)
	viper.SetDefault(RoundInterval, defaultRoundInterval)
	viper.SetDefault(VtxoTreeExpiry, defaultVtxoTreeExpiry)
	viper.SetDefault(SchedulerType, defaultSchedulerType)
	viper.SetDefault(EventDbType, defaultEventDbType)
	viper.SetDefault(TxBuilderType, defaultTxBuilderType)
	viper.SetDefault(UnilateralExitDelay, defaultUnilateralExitDelay)
	viper.SetDefault(EsploraURL, defaultEsploraURL)
	viper.SetDefault(NoMacaroons, defaultNoMacaroons)
	viper.SetDefault(BoardingExitDelay, defaultBoardingExitDelay)
	viper.SetDefault(NostrDefaultRelays, defaultNostrDefaultRelays)
	viper.SetDefault(MarketHourStartTime, defaultMarketHourStartTime)
	viper.SetDefault(MarketHourEndTime, defaultMarketHourEndTime)
	viper.SetDefault(MarketHourPeriod, defaultMarketHourPeriod)
	viper.SetDefault(MarketHourRoundInterval, defaultMarketHourInterval)
	viper.SetDefault(AllowZeroFees, defaultAllowZeroFees)
	net, err := getNetwork()
	if err != nil {
		return nil, fmt.Errorf("error while getting network: %s", err)
	}

	if err := initDatadir(); err != nil {
		return nil, fmt.Errorf("error while creating datadir: %s", err)
	}

	dbPath := filepath.Join(viper.GetString(Datadir), "db")

	return &Config{
		Datadir:                 viper.GetString(Datadir),
		WalletAddr:              viper.GetString(WalletAddr),
		RoundInterval:           viper.GetInt64(RoundInterval),
		Port:                    viper.GetUint32(Port),
		EventDbType:             viper.GetString(EventDbType),
		DbType:                  viper.GetString(DbType),
		SchedulerType:           viper.GetString(SchedulerType),
		TxBuilderType:           viper.GetString(TxBuilderType),
		NoTLS:                   viper.GetBool(NoTLS),
		DbDir:                   dbPath,
		EventDbDir:              dbPath,
		LogLevel:                viper.GetInt(LogLevel),
		Network:                 net,
		VtxoTreeExpiry:          determineLocktimeType(viper.GetInt64(VtxoTreeExpiry)),
		UnilateralExitDelay:     determineLocktimeType(viper.GetInt64(UnilateralExitDelay)),
		BoardingExitDelay:       determineLocktimeType(viper.GetInt64(BoardingExitDelay)),
		EsploraURL:              viper.GetString(EsploraURL),
		NeutrinoPeer:            viper.GetString(NeutrinoPeer),
		BitcoindRpcUser:         viper.GetString(BitcoindRpcUser),
		BitcoindRpcPass:         viper.GetString(BitcoindRpcPass),
		BitcoindRpcHost:         viper.GetString(BitcoindRpcHost),
		BitcoindZMQBlock:        viper.GetString(BitcoindZMQBlock),
		BitcoindZMQTx:           viper.GetString(BitcoindZMQTx),
		NoMacaroons:             viper.GetBool(NoMacaroons),
		TLSExtraIPs:             viper.GetStringSlice(TLSExtraIP),
		TLSExtraDomains:         viper.GetStringSlice(TLSExtraDomain),
		UnlockerType:            viper.GetString(UnlockerType),
		UnlockerFilePath:        viper.GetString(UnlockerFilePath),
		UnlockerPassword:        viper.GetString(UnlockerPassword),
		NostrDefaultRelays:      viper.GetStringSlice(NostrDefaultRelays),
		NoteUriPrefix:           viper.GetString(NoteUriPrefix),
		MarketHourStartTime:     viper.GetTime(MarketHourStartTime),
		MarketHourEndTime:       viper.GetTime(MarketHourEndTime),
		MarketHourPeriod:        viper.GetDuration(MarketHourPeriod),
		MarketHourRoundInterval: viper.GetDuration(MarketHourRoundInterval),
		OtelCollectorEndpoint:   viper.GetString(OtelCollectorEndpoint),
		AllowZeroFees:           viper.GetBool(AllowZeroFees),
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
	case common.Liquid.Name:
		return common.Liquid, nil
	case common.LiquidTestNet.Name:
		return common.LiquidTestNet, nil
	case common.LiquidRegTest.Name:
		return common.LiquidRegTest, nil
	case common.Bitcoin.Name:
		return common.Bitcoin, nil
	case common.BitcoinTestNet.Name:
		return common.BitcoinTestNet, nil
	case common.BitcoinTestNet4.Name:
		return common.BitcoinTestNet4, nil
	case common.BitcoinSigNet.Name:
		return common.BitcoinSigNet, nil
	case common.BitcoinMutinyNet.Name:
		return common.BitcoinMutinyNet, nil
	case common.BitcoinRegTest.Name:
		return common.BitcoinRegTest, nil
	default:
		return common.Network{}, fmt.Errorf("unknown network %s", viper.GetString(Network))
	}
}

func determineLocktimeType(locktime int64) common.RelativeLocktime {
	if locktime >= minAllowedSequence {
		return common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: uint32(locktime)}
	}

	return common.RelativeLocktime{Type: common.LocktimeTypeBlock, Value: uint32(locktime)}
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
	if len(c.UnlockerType) > 0 && !supportedUnlockers.supports(c.UnlockerType) {
		return fmt.Errorf("unlocker type not supported, please select one of: %s", supportedUnlockers)
	}
	if c.RoundInterval < 2 {
		return fmt.Errorf("invalid round interval, must be at least 2 seconds")
	}
	if !supportedNetworks.supports(c.Network.Name) {
		return fmt.Errorf("invalid network, must be one of: %s", supportedNetworks)
	}
	if c.VtxoTreeExpiry.Type == common.LocktimeTypeBlock {
		if c.SchedulerType != "block" {
			return fmt.Errorf("scheduler type must be block if vtxo tree expiry is expressed in blocks")
		}
	} else { // seconds
		if c.SchedulerType != "gocron" {
			return fmt.Errorf("scheduler type must be gocron if vtxo tree expiry is expressed in seconds")
		}

		// vtxo tree expiry must be a multiple of 512 if expressed in seconds
		if c.VtxoTreeExpiry.Value%minAllowedSequence != 0 {
			c.VtxoTreeExpiry.Value -= c.VtxoTreeExpiry.Value % minAllowedSequence
			log.Infof(
				"vtxo tree expiry must be a multiple of %d, rounded to %d",
				minAllowedSequence, c.VtxoTreeExpiry,
			)
		}
	}

	if c.UnilateralExitDelay.Type == common.LocktimeTypeBlock {
		return fmt.Errorf(
			"invalid unilateral exit delay, must at least %d", minAllowedSequence,
		)
	}

	if c.BoardingExitDelay.Type == common.LocktimeTypeBlock {
		return fmt.Errorf(
			"invalid boarding exit delay, must at least %d", minAllowedSequence,
		)
	}

	if c.UnilateralExitDelay.Value%minAllowedSequence != 0 {
		c.UnilateralExitDelay.Value -= c.UnilateralExitDelay.Value % minAllowedSequence
		log.Infof(
			"unilateral exit delay must be a multiple of %d, rounded to %d",
			minAllowedSequence, c.UnilateralExitDelay,
		)
	}

	if c.BoardingExitDelay.Value%minAllowedSequence != 0 {
		c.BoardingExitDelay.Value -= c.BoardingExitDelay.Value % minAllowedSequence
		log.Infof(
			"boarding exit delay must be a multiple of %d, rounded to %d",
			minAllowedSequence, c.BoardingExitDelay,
		)
	}

	if len(c.NostrDefaultRelays) == 0 {
		return fmt.Errorf("missing nostr default relays")
	}

	for _, relay := range c.NostrDefaultRelays {
		if !nostr.IsValidRelayURL(relay) {
			return fmt.Errorf("invalid nostr relay url: %s", relay)
		}
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
		dataStoreConfig = []interface{}{c.DbDir}
	default:
		return fmt.Errorf("unknown db type")
	}

	svc, err = db.NewService(db.ServiceConfig{
		EventStoreType:   c.EventDbType,
		DataStoreType:    c.DbType,
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
		svc, err := liquidwallet.NewService(c.WalletAddr, c.EsploraURL)
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
	case c.BitcoindZMQBlock != "" && c.BitcoindZMQTx != "" && c.BitcoindRpcUser != "" && c.BitcoindRpcPass != "":
		svc, err = btcwallet.NewService(btcwallet.WalletConfig{
			Datadir: c.DbDir,
			Network: c.Network,
		}, btcwallet.WithBitcoindZMQ(c.BitcoindZMQBlock, c.BitcoindZMQTx, c.BitcoindRpcHost, c.BitcoindRpcUser, c.BitcoindRpcPass))
	case c.BitcoindRpcUser != "" && c.BitcoindRpcPass != "":
		svc, err = btcwallet.NewService(btcwallet.WalletConfig{
			Datadir: c.DbDir,
			Network: c.Network,
		}, btcwallet.WithPollingBitcoind(c.BitcoindRpcHost, c.BitcoindRpcUser, c.BitcoindRpcPass))
	default:
		// Default to Neutrino for Bitcoin mainnet or when NeutrinoPeer is explicitly set
		if len(c.EsploraURL) == 0 {
			return fmt.Errorf("missing esplora url, covenant-less ark requires ARK_ESPLORA_URL to be set")
		}
		svc, err = btcwallet.NewService(btcwallet.WalletConfig{
			Datadir: c.DbDir,
			Network: c.Network,
		}, btcwallet.WithNeutrino(c.NeutrinoPeer, c.EsploraURL))
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
			c.wallet, c.Network, c.VtxoTreeExpiry, c.BoardingExitDelay,
		)
	case "covenantless":
		svc = cltxbuilder.NewTxBuilder(
			c.wallet, c.Network, c.VtxoTreeExpiry, c.BoardingExitDelay,
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
	c.scanner = c.wallet
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
			c.Network, c.RoundInterval, c.VtxoTreeExpiry, c.UnilateralExitDelay, c.BoardingExitDelay, c.NostrDefaultRelays,
			c.wallet, c.repo, c.txBuilder, c.scanner, c.scheduler, c.NoteUriPrefix,
			c.MarketHourStartTime, c.MarketHourEndTime, c.MarketHourPeriod, c.MarketHourRoundInterval,
		)
		if err != nil {
			return err
		}

		c.svc = svc
		return nil
	}

	svc, err := application.NewCovenantlessService(
		c.Network, c.RoundInterval, c.VtxoTreeExpiry, c.UnilateralExitDelay, c.BoardingExitDelay, c.NostrDefaultRelays,
		c.wallet, c.repo, c.txBuilder, c.scanner, c.scheduler, c.NoteUriPrefix,
		c.MarketHourStartTime, c.MarketHourEndTime, c.MarketHourPeriod, c.MarketHourRoundInterval,
		c.AllowZeroFees,
	)
	if err != nil {
		return err
	}

	c.svc = svc
	return nil
}

func (c *Config) adminService() error {
	unit := ports.UnixTime
	if c.VtxoTreeExpiry.Value < minAllowedSequence {
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
