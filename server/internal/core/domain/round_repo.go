package domain

import (
	"context"
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
	GetSweepableRounds(ctx context.Context) ([]Round, error)
	GetRoundsIds(ctx context.Context, startedAfter int64, startedBefore int64) ([]string, error)
	GetSweptRounds(ctx context.Context) ([]Round, error)
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
