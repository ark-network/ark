module github.com/ark-network/noah

go 1.21.0

replace github.com/ark-network/ark/common => ../common

require (
	github.com/ark-network/ark/common v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0
	github.com/urfave/cli/v2 v2.25.7
	golang.org/x/crypto v0.15.0
	golang.org/x/term v0.14.0
)

require (
	github.com/btcsuite/btcd/btcutil v1.1.3 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	golang.org/x/sys v0.14.0 // indirect
)
