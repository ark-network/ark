module github.com/ark-network/ark

go 1.21.0

replace github.com/ark-network/ark/common => ./pkg/common

require (
	github.com/btcsuite/btcd/btcec/v2 v2.1.3
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1
	github.com/sirupsen/logrus v1.9.3
)

require (
	github.com/btcsuite/btcd v0.23.0 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // indirect
)

require (
	github.com/btcsuite/btcd/btcutil v1.1.3
	github.com/stretchr/testify v1.8.4 // indirect
	github.com/urfave/cli/v2 v2.25.7
	golang.org/x/sys v0.14.0 // indirect
	golang.org/x/term v0.14.0
)
