package store

import (
	"context"

	"github.com/ark-network/ark/common"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	InMemoryStore = "inmemory"
	FileStore     = "file"
)

type StoreData struct {
	AspUrl                     string
	AspPubkey                  *secp256k1.PublicKey
	WalletType                 string
	ClientType                 string
	Network                    common.Network
	RoundLifetime              int64
	UnilateralExitDelay        int64
	Dust                       uint64
	BoardingDescriptorTemplate string
}

type ConfigStore interface {
	GetType() string
	GetDatadir() string
	AddData(ctx context.Context, data StoreData) error
	GetData(ctx context.Context) (*StoreData, error)
	CleanData(ctx context.Context) error
}
