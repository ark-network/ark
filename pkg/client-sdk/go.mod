module github.com/ark-network/ark/pkg/client-sdk

go 1.23.1

replace github.com/btcsuite/btcd/btcec/v2 => github.com/btcsuite/btcd/btcec/v2 v2.3.3

require (
	github.com/btcsuite/btcd v0.24.3-0.20240921052913-67b8efd3ba53
	github.com/btcsuite/btcd/btcec/v2 v2.3.4
	github.com/btcsuite/btcd/btcutil v1.1.5
	github.com/btcsuite/btcd/btcutil/psbt v1.1.9
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/btcsuite/btcwallet v0.16.10-0.20240718224643-db3a4a2543bd
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0
	github.com/dgraph-io/badger/v4 v4.3.0
	github.com/go-openapi/errors v0.22.0
	github.com/go-openapi/runtime v0.28.0
	github.com/go-openapi/strfmt v0.23.0
	github.com/go-openapi/swag v0.23.0
	github.com/go-openapi/validate v0.24.0
	github.com/golang-migrate/migrate/v4 v4.17.1
	github.com/lightningnetwork/lnd v0.18.2-beta
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.10.0
	github.com/timshannon/badgerhold/v4 v4.0.3
	github.com/vulpemventures/go-bip32 v0.0.0-20200624192635-867c159da4d7
	golang.org/x/crypto v0.35.0
	golang.org/x/exp v0.0.0-20250106191152-7588d65b2ba8
	google.golang.org/grpc v1.69.4
	modernc.org/sqlite v1.33.1
)

require (
	dario.cat/mergo v1.0.1 // indirect
	github.com/FactomProject/basen v0.0.0-20150613233007-fe3947df716e // indirect
	github.com/FactomProject/btcutilecc v0.0.0-20130527213604-d3a63a5752ec // indirect
	github.com/aead/siphash v1.0.1 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/btcsuite/btcwallet/wallet/txauthor v1.3.4 // indirect
	github.com/btcsuite/btcwallet/wallet/txrules v1.2.1 // indirect
	github.com/btcsuite/btcwallet/wallet/txsizes v1.2.4 // indirect
	github.com/btcsuite/btcwallet/walletdb v1.4.2 // indirect
	github.com/btcsuite/btcwallet/wtxmgr v1.5.3 // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/lru v1.1.3 // indirect
	github.com/dgraph-io/ristretto v1.0.0 // indirect
	github.com/docker/cli v27.1.1+incompatible // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fergusstrange/embedded-postgres v1.28.0 // indirect
	github.com/go-errors/errors v1.5.1 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/analysis v0.23.0 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/loads v0.22.0 // indirect
	github.com/go-openapi/spec v0.21.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/flatbuffers v24.3.25+incompatible // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgtype v1.14.3 // indirect
	github.com/jackc/pgx/v4 v4.18.3 // indirect
	github.com/jackc/pgx/v5 v5.6.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jessevdk/go-flags v1.6.1 // indirect
	github.com/jonboulle/clockwork v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/lightninglabs/gozmq v0.0.0-20191113021534-d20a764486bf // indirect
	github.com/lightninglabs/neutrino v0.16.1-0.20240425105051-602843d34ffd // indirect
	github.com/lightninglabs/neutrino/cache v1.1.2 // indirect
	github.com/lightningnetwork/lightning-onion v1.2.1-0.20240712235311-98bd56499dfb // indirect
	github.com/lightningnetwork/lnd/clock v1.1.1 // indirect
	github.com/lightningnetwork/lnd/fn v1.2.1 // indirect
	github.com/lightningnetwork/lnd/healthcheck v1.2.5 // indirect
	github.com/lightningnetwork/lnd/kvdb v1.4.10 // indirect
	github.com/lightningnetwork/lnd/queue v1.1.1 // indirect
	github.com/lightningnetwork/lnd/sqldb v1.0.3 // indirect
	github.com/lightningnetwork/lnd/ticker v1.1.1 // indirect
	github.com/lightningnetwork/lnd/tlv v1.2.6 // indirect
	github.com/lightningnetwork/lnd/tor v1.1.3 // indirect
	github.com/ltcsuite/ltcd v0.23.5 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/miekg/dns v1.1.61 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opencontainers/runc v1.2.4 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/ory/dockertest/v3 v3.11.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.20.2 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/tmc/grpc-websocket-proxy v0.0.0-20220101234140-673ab2c3ae75 // indirect
	github.com/xiang90/probing v0.0.0-20221125231312-a49e3df8f510 // indirect
	go.etcd.io/bbolt v1.3.10 // indirect
	go.etcd.io/etcd/api/v3 v3.5.15 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.15 // indirect
	go.etcd.io/etcd/client/v3 v3.5.15 // indirect
	go.etcd.io/etcd/server/v3 v3.5.15 // indirect
	go.mongodb.org/mongo-driver v1.14.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.53.0 // indirect
	go.opentelemetry.io/otel v1.34.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.34.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.28.0 // indirect
	go.opentelemetry.io/otel/metric v1.34.0 // indirect
	go.opentelemetry.io/otel/sdk v1.34.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.34.0 // indirect
	go.opentelemetry.io/otel/trace v1.34.0 // indirect
	go.opentelemetry.io/proto/otlp v1.5.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/net v0.36.0 // indirect
	golang.org/x/sync v0.12.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/term v0.29.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	golang.org/x/time v0.6.0 // indirect
	google.golang.org/genproto v0.0.0-20240812133136-8ffd90a71988 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250115164207-1a7da9e5054f // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
	modernc.org/gc/v3 v3.0.0-20240801135723-a856999a2e4a // indirect
	modernc.org/libc v1.59.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/strutil v1.2.0 // indirect
	modernc.org/token v1.1.0 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)
