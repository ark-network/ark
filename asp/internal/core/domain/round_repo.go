package domain

import (
	"context"
)

type ExpiredRound struct {
	Round
	ExpiredOutputs []int // indexes of Round.SharedOutputs that are expired
}

type RoundEventRepository interface {
	Save(ctx context.Context, id string, events ...RoundEvent) error
	Load(ctx context.Context, id string) (*Round, error)
}

type RoundRepository interface {
	AddOrUpdateRound(ctx context.Context, round Round) error
	GetCurrentRound(ctx context.Context) (*Round, error)
	GetRoundWithId(ctx context.Context, id string) (*Round, error)
	GetRoundWithTxid(ctx context.Context, txid string) (*Round, error)
	GetExpiredOutputs(ctx context.Context) ([]ExpiredRound, error)
}

type VtxoRepository interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) error
	SpendVtxos(ctx context.Context, vtxos []VtxoKey) error
	GetVtxos(ctx context.Context, vtxos []VtxoKey) ([]Vtxo, error)
	GetSpendableVtxosWithPubkey(ctx context.Context, pubkey string) ([]Vtxo, error)
	SweepVtxos(ctx context.Context, vtxos []VtxoKey) error
}
