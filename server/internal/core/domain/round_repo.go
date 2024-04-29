package domain

import (
	"context"
)

type RoundEventRepository interface {
	Save(ctx context.Context, id string, events ...RoundEvent) (*Round, error)
	Load(ctx context.Context, id string) (*Round, error)
}

type RoundRepository interface {
	AddOrUpdateRound(ctx context.Context, round Round) error
	GetCurrentRound(ctx context.Context) (*Round, error)
	GetRoundWithId(ctx context.Context, id string) (*Round, error)
	GetRoundWithTxid(ctx context.Context, txid string) (*Round, error)
	GetSweepableRounds(ctx context.Context) ([]Round, error)
}

type VtxoRepository interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) error
	SpendVtxos(ctx context.Context, vtxos []VtxoKey, txid string) error
	RedeemVtxos(ctx context.Context, vtxos []VtxoKey) ([]Vtxo, error)
	GetVtxos(ctx context.Context, vtxos []VtxoKey) ([]Vtxo, error)
	GetVtxosForRound(ctx context.Context, txid string) ([]Vtxo, error)
	SweepVtxos(ctx context.Context, vtxos []VtxoKey) error
	GetAllVtxos(ctx context.Context, pubkey string) ([]Vtxo, []Vtxo, error)
	UpdateExpireAt(ctx context.Context, vtxos []VtxoKey, expireAt int64) error
}
