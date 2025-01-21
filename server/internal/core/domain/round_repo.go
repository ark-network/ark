package domain

import (
	"context"

	"github.com/ark-network/ark/common/tree"
)

type RoundEventRepository interface {
	Save(ctx context.Context, id string, events ...RoundEvent) (*Round, error)
	Load(ctx context.Context, id string) (*Round, error)
	RegisterEventsHandler(func(*Round))
	Close()
}

type RoundRepository interface {
	AddOrUpdateRound(ctx context.Context, round Round) error
	GetRoundWithId(ctx context.Context, id string) (*Round, error)
	GetRoundWithTxid(ctx context.Context, txid string) (*Round, error)
	GetVtxoTreeWithTxid(ctx context.Context, txid string) (tree.VtxoTree, error)
	GetExpiredRoundsTxid(ctx context.Context) ([]string, error)
	GetRoundsIds(ctx context.Context, startedAfter int64, startedBefore int64) ([]string, error)
	GetSweptRoundsConnectorAddress(ctx context.Context) ([]string, error)
	Close()
}

type VtxoRepository interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) error
	SpendVtxos(ctx context.Context, vtxos []VtxoKey, txid string) error
	RedeemVtxos(ctx context.Context, vtxos []VtxoKey) error
	GetVtxos(ctx context.Context, vtxos []VtxoKey) ([]Vtxo, error)
	GetVtxosForRound(ctx context.Context, txid string) ([]Vtxo, error)
	SweepVtxos(ctx context.Context, vtxos []VtxoKey) error
	GetAllVtxos(ctx context.Context, pubkey string) ([]Vtxo, []Vtxo, error)
	GetAllSweepableVtxos(ctx context.Context) ([]Vtxo, error)
	UpdateExpireAt(ctx context.Context, vtxos []VtxoKey, expireAt int64) error
	Close()
}

type MarketHourRepo interface {
	Get(ctx context.Context) (*MarketHour, error)
	Upsert(ctx context.Context, marketHour MarketHour) error
	Close()
}
