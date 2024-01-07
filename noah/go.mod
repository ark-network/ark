module github.com/ark-network/noah

go 1.21.0

replace github.com/ark-network/ark/common => ../common

replace github.com/ark-network/ark => ../asp

require (
	github.com/ark-network/ark v0.0.0-00010101000000-000000000000
	github.com/ark-network/ark/common v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd v0.23.4
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.3
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0
	github.com/urfave/cli/v2 v2.26.0
	golang.org/x/crypto v0.16.0
	golang.org/x/term v0.15.0
)

require (
	github.com/btcsuite/btcd/btcutil/psbt v1.1.8 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.1 // indirect
	github.com/vulpemventures/fastsha256 v0.0.0-20160815193821-637e65642941 // indirect
)

require (
	github.com/btcsuite/btcd/btcutil v1.1.3 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.3 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.18.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/vulpemventures/go-elements v0.5.1
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto v0.0.0-20231127180814-3a041ad873d4 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20231127180814-3a041ad873d4 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231127180814-3a041ad873d4 // indirect
	google.golang.org/grpc v1.59.0
	google.golang.org/protobuf v1.31.0 // indirect
)
