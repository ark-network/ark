module github.com/ark-network/ark/common

go 1.21.0

replace github.com/ark-network/ark => ../server

require (
	github.com/ark-network/ark v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd v0.24.0
	github.com/btcsuite/btcd/btcec/v2 v2.3.3
	github.com/btcsuite/btcd/btcutil v1.1.5
	github.com/btcsuite/btcd/btcutil/psbt v1.1.9
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0
	github.com/improbable-eng/grpc-web v0.15.0
	github.com/stretchr/testify v1.9.0
	google.golang.org/grpc v1.64.0
)

require (
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/cenkalti/backoff/v4 v4.1.1 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.1 // indirect
	github.com/desertbit/timer v0.0.0-20180107155436-c41aec40b27f // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.20.0 // indirect
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/rs/cors v1.7.0 // indirect
	github.com/vulpemventures/fastsha256 v0.0.0-20160815193821-637e65642941 // indirect
	golang.org/x/crypto v0.23.0 // indirect
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/text v0.15.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240528184218-531527333157 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240528184218-531527333157 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
	nhooyr.io/websocket v1.8.6 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/vulpemventures/go-elements v0.5.3
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
