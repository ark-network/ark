package config

import (
	"context"
	"fmt"
	"github.com/ark-network/ark/server/internal/infrastructure/live-store/inmemory"
	"github.com/ark-network/ark/server/internal/infrastructure/live-store/redis"
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
	txbuilder "github.com/ark-network/ark/server/internal/infrastructure/tx-builder/covenantless"
	bitcointxdecoder "github.com/ark-network/ark/server/internal/infrastructure/tx-decoder/bitcoin"
	envunlocker "github.com/ark-network/ark/server/internal/infrastructure/unlocker/env"
	fileunlocker "github.com/ark-network/ark/server/internal/infrastructure/unlocker/file"
	walletclient "github.com/ark-network/ark/server/internal/infrastructure/wallet"
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
		"covenantless": {},
	}
	supportedUnlockers = supportedType{
		"env":  {},
		"file": {},
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
	SchedulerType       string
	TxBuilderType       string
	LiveStoreType       string
	WalletAddr          string
	VtxoTreeExpiry      common.RelativeLocktime
	UnilateralExitDelay common.RelativeLocktime
	BoardingExitDelay   common.RelativeLocktime
	NoteUriPrefix       string

	MarketHourStartTime     time.Time
	MarketHourEndTime       time.Time
	MarketHourPeriod        time.Duration
	MarketHourRoundInterval time.Duration
	OtelCollectorEndpoint   string

	EsploraURL string

	UnlockerType     string
	UnlockerFilePath string // file unlocker
	UnlockerPassword string // env unlocker

	RoundMaxParticipantsCount int64
	UtxoMaxAmount             int64
	UtxoMinAmount             int64
	VtxoMaxAmount             int64
	VtxoMinAmount             int64

	repo      ports.RepoManager
	svc       application.Service
	adminSvc  application.AdminService
	wallet    ports.WalletService
	txBuilder ports.TxBuilder
	scanner   ports.BlockchainScanner
	scheduler ports.SchedulerService
	unlocker  ports.Unlocker
	liveStore ports.LiveStore
	network   *common.Network
}

var (
	Datadir                   = "DATADIR"
	WalletAddr                = "WALLET_ADDR"
	RoundInterval             = "ROUND_INTERVAL"
	Port                      = "PORT"
	EventDbType               = "EVENT_DB_TYPE"
	DbType                    = "DB_TYPE"
	SchedulerType             = "SCHEDULER_TYPE"
	TxBuilderType             = "TX_BUILDER_TYPE"
	LiveStoreType             = "LIVE_STORE_TYPE"
	LogLevel                  = "LOG_LEVEL"
	VtxoTreeExpiry            = "VTXO_TREE_EXPIRY"
	UnilateralExitDelay       = "UNILATERAL_EXIT_DELAY"
	BoardingExitDelay         = "BOARDING_EXIT_DELAY"
	EsploraURL                = "ESPLORA_URL"
	NoMacaroons               = "NO_MACAROONS"
	NoTLS                     = "NO_TLS"
	TLSExtraIP                = "TLS_EXTRA_IP"
	TLSExtraDomain            = "TLS_EXTRA_DOMAIN"
	UnlockerType              = "UNLOCKER_TYPE"
	UnlockerFilePath          = "UNLOCKER_FILE_PATH"
	UnlockerPassword          = "UNLOCKER_PASSWORD"
	NoteUriPrefix             = "NOTE_URI_PREFIX"
	MarketHourStartTime       = "MARKET_HOUR_START_TIME"
	MarketHourEndTime         = "MARKET_HOUR_END_TIME"
	MarketHourPeriod          = "MARKET_HOUR_PERIOD"
	MarketHourRoundInterval   = "MARKET_HOUR_ROUND_INTERVAL"
	OtelCollectorEndpoint     = "OTEL_COLLECTOR_ENDPOINT"
	RoundMaxParticipantsCount = "ROUND_MAX_PARTICIPANTS_COUNT"
	UtxoMaxAmount             = "UTXO_MAX_AMOUNT"
	VtxoMaxAmount             = "VTXO_MAX_AMOUNT"
	UtxoMinAmount             = "UTXO_MIN_AMOUNT"
	VtxoMinAmount             = "VTXO_MIN_AMOUNT"

	defaultDatadir             = common.AppDataDir("arkd", false)
	defaultRoundInterval       = 30
	DefaultPort                = 7070
	defaultDbType              = "sqlite"
	defaultEventDbType         = "badger"
	defaultSchedulerType       = "gocron"
	defaultTxBuilderType       = "covenantless"
	defaultLiveStoreType       = "redis"
	defaultEsploraURL          = "https://blockstream.info/api"
	defaultLogLevel            = 4
	defaultVtxoTreeExpiry      = 604672  // 7 days
	defaultUnilateralExitDelay = 86400   // 24 hours
	defaultBoardingExitDelay   = 7776000 // 3 months
	defaultNoMacaroons         = false
	defaultNoTLS               = true
	defaultMarketHourStartTime = time.Now()
	defaultMarketHourEndTime   = defaultMarketHourStartTime.Add(time.Hour)
	defaultMarketHourPeriod    = 24 * time.Hour
	defaultMarketHourInterval  = time.Duration(defaultRoundInterval) * time.Second
	defaultUtxoMaxAmount       = -1 // -1 means no limit (default), 0 means boarding not allowed
	defaultUtxoMinAmount       = -1 // -1 means native dust limit (default)
	defaultVtxoMinAmount       = -1 // -1 means native dust limit (default)
	defaultVtxoMaxAmount       = -1 // -1 means no limit (default)

	defaultRoundMaxParticipantsCount = 128
)

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("ARK")
	viper.AutomaticEnv()

	viper.SetDefault(Datadir, defaultDatadir)
	viper.SetDefault(Port, DefaultPort)
	viper.SetDefault(DbType, defaultDbType)
	viper.SetDefault(NoTLS, defaultNoTLS)
	viper.SetDefault(LogLevel, defaultLogLevel)
	viper.SetDefault(RoundInterval, defaultRoundInterval)
	viper.SetDefault(VtxoTreeExpiry, defaultVtxoTreeExpiry)
	viper.SetDefault(SchedulerType, defaultSchedulerType)
	viper.SetDefault(EventDbType, defaultEventDbType)
	viper.SetDefault(TxBuilderType, defaultTxBuilderType)
	viper.SetDefault(UnilateralExitDelay, defaultUnilateralExitDelay)
	viper.SetDefault(EsploraURL, defaultEsploraURL)
	viper.SetDefault(NoMacaroons, defaultNoMacaroons)
	viper.SetDefault(BoardingExitDelay, defaultBoardingExitDelay)
	viper.SetDefault(MarketHourStartTime, defaultMarketHourStartTime)
	viper.SetDefault(MarketHourEndTime, defaultMarketHourEndTime)
	viper.SetDefault(MarketHourPeriod, defaultMarketHourPeriod)
	viper.SetDefault(MarketHourRoundInterval, defaultMarketHourInterval)
	viper.SetDefault(RoundMaxParticipantsCount, defaultRoundMaxParticipantsCount)
	viper.SetDefault(UtxoMaxAmount, defaultUtxoMaxAmount)
	viper.SetDefault(UtxoMinAmount, defaultUtxoMinAmount)
	viper.SetDefault(VtxoMaxAmount, defaultVtxoMaxAmount)
	viper.SetDefault(VtxoMinAmount, defaultVtxoMinAmount)
	viper.SetDefault(LiveStoreType, defaultLiveStoreType)

	if err := initDatadir(); err != nil {
		return nil, fmt.Errorf("error while creating datadir: %s", err)
	}

	dbPath := filepath.Join(viper.GetString(Datadir), "db")

	return &Config{
		Datadir:                   viper.GetString(Datadir),
		WalletAddr:                viper.GetString(WalletAddr),
		RoundInterval:             viper.GetInt64(RoundInterval),
		Port:                      viper.GetUint32(Port),
		EventDbType:               viper.GetString(EventDbType),
		DbType:                    viper.GetString(DbType),
		SchedulerType:             viper.GetString(SchedulerType),
		TxBuilderType:             viper.GetString(TxBuilderType),
		LiveStoreType:             viper.GetString(LiveStoreType),
		NoTLS:                     viper.GetBool(NoTLS),
		DbDir:                     dbPath,
		EventDbDir:                dbPath,
		LogLevel:                  viper.GetInt(LogLevel),
		VtxoTreeExpiry:            determineLocktimeType(viper.GetInt64(VtxoTreeExpiry)),
		UnilateralExitDelay:       determineLocktimeType(viper.GetInt64(UnilateralExitDelay)),
		BoardingExitDelay:         determineLocktimeType(viper.GetInt64(BoardingExitDelay)),
		EsploraURL:                viper.GetString(EsploraURL),
		NoMacaroons:               viper.GetBool(NoMacaroons),
		TLSExtraIPs:               viper.GetStringSlice(TLSExtraIP),
		TLSExtraDomains:           viper.GetStringSlice(TLSExtraDomain),
		UnlockerType:              viper.GetString(UnlockerType),
		UnlockerFilePath:          viper.GetString(UnlockerFilePath),
		UnlockerPassword:          viper.GetString(UnlockerPassword),
		NoteUriPrefix:             viper.GetString(NoteUriPrefix),
		MarketHourStartTime:       viper.GetTime(MarketHourStartTime),
		MarketHourEndTime:         viper.GetTime(MarketHourEndTime),
		MarketHourPeriod:          viper.GetDuration(MarketHourPeriod),
		MarketHourRoundInterval:   viper.GetDuration(MarketHourRoundInterval),
		OtelCollectorEndpoint:     viper.GetString(OtelCollectorEndpoint),
		RoundMaxParticipantsCount: viper.GetInt64(RoundMaxParticipantsCount),
		UtxoMaxAmount:             viper.GetInt64(UtxoMaxAmount),
		UtxoMinAmount:             viper.GetInt64(UtxoMinAmount),
		VtxoMaxAmount:             viper.GetInt64(VtxoMaxAmount),
		VtxoMinAmount:             viper.GetInt64(VtxoMinAmount),
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
	if err := c.liveStoreService(); err != nil {
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

func (c *Config) IndexerService() (application.IndexerService, error) {
	pubKey, err := c.wallet.GetPubkey(context.Background())
	if err != nil {
		return nil, err
	}

	return application.NewIndexerService(pubKey, c.repo), nil
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

	txDecoder := bitcointxdecoder.NewService()

	svc, err = db.NewService(db.ServiceConfig{
		EventStoreType:   c.EventDbType,
		DataStoreType:    c.DbType,
		EventStoreConfig: eventStoreConfig,
		DataStoreConfig:  dataStoreConfig,
	}, txDecoder)
	if err != nil {
		return err
	}

	c.repo = svc
	return nil
}

func (c *Config) walletService() error {
	arkWallet := viper.GetString(WalletAddr)
	if arkWallet == "" {
		return fmt.Errorf("ark wallet address not set")
	}

	walletSvc, network, err := walletclient.New(arkWallet)
	if err != nil {
		return err
	}

	c.wallet = walletSvc
	c.network = network
	return nil
}

func (c *Config) txBuilderService() error {
	var svc ports.TxBuilder
	var err error
	switch c.TxBuilderType {
	case "covenantless":
		svc = txbuilder.NewTxBuilder(
			c.wallet, *c.network, c.VtxoTreeExpiry, c.BoardingExitDelay,
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

func (c *Config) liveStoreService() error {
	if c.txBuilder == nil {
		return fmt.Errorf("tx builder not set")
	}

	var liveStoreSvc ports.LiveStore
	var err error
	switch c.LiveStoreType {
	case "inmemory":
		liveStoreSvc = inmemory.NewLiveStore(c.txBuilder)
	case "redis":
		liveStoreSvc = redis.NewLiveStore()
	default:
		err = fmt.Errorf("unknown liveStore type")
	}

	if err != nil {
		return err
	}

	c.liveStore = liveStoreSvc
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
	svc, err := application.NewService(
		*c.network, c.RoundInterval, c.VtxoTreeExpiry, c.UnilateralExitDelay, c.BoardingExitDelay,
		c.wallet, c.repo, c.txBuilder, c.scanner, c.scheduler, c.NoteUriPrefix,
		c.MarketHourStartTime, c.MarketHourEndTime, c.MarketHourPeriod, c.MarketHourRoundInterval,
		c.RoundMaxParticipantsCount, c.UtxoMaxAmount, c.UtxoMinAmount, c.VtxoMaxAmount, c.VtxoMinAmount, c.liveStore,
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
