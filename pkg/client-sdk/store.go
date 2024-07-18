package arksdk

import (
	"context"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type ConfigStore interface {
	GetAspUrl(ctx context.Context) (string, error)
	GetAspPubKeyHex(ctx context.Context) (string, error)
	GetTransportProtocol(ctx context.Context) (TransportProtocol, error)
	GetExplorerUrl(ctx context.Context) (string, error)
	GetNetwork(ctx context.Context) (string, error)

	SetAspUrl(aspUrl string)
	SetAspPubKeyHex(aspPubKeyHex string)
	SetTransportProtocol(protocol TransportProtocol)
	SetExplorerUrl(explorerUrl string)
	SetNetwork(net string)

	Save(ctx context.Context) error
}

type WalletStore interface {
	CreatePrivateKey() (*secp256k1.PrivateKey, error)
	GetPrivateKeyHex() (string, error)
	Save(ctx context.Context) error
}
