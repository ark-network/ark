package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/spf13/viper"
)

type Config struct {
	Datadir                 string
	WalletAddr              string
	RoundInterval           int64
	Port                    uint32
	EventDbType             string
	DbType                  string
	DbDir                   string
	DbMigrationPath         string
	SchedulerType           string
	TxBuilderType           string
	NoTLS                   bool
	NoMacaroons             bool
	Network                 common.Network
	LogLevel                int
	VtxoTreeExpiry          int64
	UnilateralExitDelay     int64
	BoardingExitDelay       int64
	EsploraURL              string
	NeutrinoPeer            string
	BitcoindRpcUser         string
	BitcoindRpcPass         string
	BitcoindRpcHost         string
	BitcoindZMQBlock        string
	BitcoindZMQTx           string
	TLSExtraIPs             []string
	TLSExtraDomains         []string
	UnlockerType            string
	UnlockerFilePath        string
	UnlockerPassword        string
	NostrDefaultRelays      []string
	NoteUriPrefix           string
	MarketHourStartTime     time.Time
	MarketHourEndTime       time.Time
	MarketHourPeriod        time.Duration
	MarketHourRoundInterval time.Duration
	OtelCollectorEndpoint   string

	// TODO remove with transactions version 3
	AllowZeroFees bool
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
		DbDir:                   filepath.Join(viper.GetString(Datadir), "db"),
		LogLevel:                viper.GetInt(LogLevel),
		Network:                 net,
		VtxoTreeExpiry:          viper.GetInt64(VtxoTreeExpiry),
		UnilateralExitDelay:     viper.GetInt64(UnilateralExitDelay),
		BoardingExitDelay:       viper.GetInt64(BoardingExitDelay),
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
