module github.com/ark-network/ark/client

go 1.23.1

replace github.com/ark-network/ark/pkg/client-sdk => ../pkg/client-sdk

replace github.com/btcsuite/btcd/btcec/v2 => github.com/btcsuite/btcd/btcec/v2 v2.3.3

require (
	github.com/ark-network/ark/common v0.0.0-20240910195127-ab2c9785d00e
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0
	github.com/urfave/cli/v2 v2.27.4
	golang.org/x/crypto v0.26.0
	golang.org/x/term v0.23.0
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/aead/siphash v1.0.1 // indirect
	github.com/btcsuite/btcd v0.24.2 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.4 // indirect
	github.com/btcsuite/btcd/btcutil/psbt v1.1.9 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/btcsuite/btcwallet v0.16.10-0.20240718224643-db3a4a2543bd // indirect
	github.com/btcsuite/btcwallet/wallet/txauthor v1.3.4 // indirect
	github.com/btcsuite/btcwallet/wallet/txrules v1.2.1 // indirect
	github.com/btcsuite/btcwallet/wallet/txsizes v1.2.4 // indirect
	github.com/btcsuite/btcwallet/walletdb v1.4.2 // indirect
	github.com/btcsuite/btcwallet/wtxmgr v1.5.3 // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/continuity v0.4.3 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.1 // indirect
	github.com/decred/dcrd/lru v1.1.3 // indirect
	github.com/docker/docker v27.1.1+incompatible // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lightninglabs/gozmq v0.0.0-20191113021534-d20a764486bf // indirect
	github.com/lightninglabs/neutrino v0.16.1-0.20240425105051-602843d34ffd // indirect
	github.com/lightninglabs/neutrino/cache v1.1.2 // indirect
	github.com/lightningnetwork/lnd v0.18.2-beta // indirect
	github.com/lightningnetwork/lnd/clock v1.1.1 // indirect
	github.com/lightningnetwork/lnd/fn v1.2.1 // indirect
	github.com/lightningnetwork/lnd/queue v1.1.1 // indirect
	github.com/lightningnetwork/lnd/ticker v1.1.1 // indirect
	github.com/lightningnetwork/lnd/tlv v1.2.6 // indirect
	github.com/ltcsuite/ltcd/chaincfg/chainhash v1.0.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/opencontainers/runc v1.1.13 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/vulpemventures/fastsha256 v0.0.0-20160815193821-637e65642941 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	go.etcd.io/etcd/client/v2 v2.305.15 // indirect
	go.etcd.io/etcd/pkg/v3 v3.5.15 // indirect
	go.etcd.io/etcd/raft/v3 v3.5.15 // indirect
	go.opentelemetry.io/otel v1.30.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.28.0 // indirect
	go.opentelemetry.io/proto/otlp v1.3.1 // indirect
	golang.org/x/exp v0.0.0-20240808152545-0cdaa3abc0fa // indirect
	golang.org/x/sync v0.8.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.4 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/vulpemventures/go-elements v0.5.4 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	golang.org/x/sys v0.24.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)
