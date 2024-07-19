package store

import (
	"context"

	"github.com/ark-network/ark/common"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type StoreData struct {
	AspUrl              string
	AspPubkey           *secp256k1.PublicKey
	WalletType          string
	ClientType          string
	ExplorerURL         string
	Network             common.Network
	RoundLifetime       int64
	UnilateralExitDelay int64
	MinRelayFee         uint64
}

type Store interface {
	AddData(ctx context.Context, data StoreData) error
	GetData(ctx context.Context) (*StoreData, error)
	CleanData(ctx context.Context) error
}

type StoreFactory func(args ...interface{}) (Store, error)
