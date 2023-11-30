package domain

import "context"

type RoundEventRepository interface {
	Save(ctx context.Context, events ...RoundEvent) error
	Load(ctx context.Context, id string) (*Round, error)
}

type RoundRepository interface {
	AddRound(ctx context.Context, round *Round) error
	GetCurrentRound(ctx context.Context) (*Round, error)
	GetRoundWithId(ctx context.Context, id string) (*Round, error)
	GetRoundWithTxid(ctx context.Context, txid string) (*Round, error)
	UpdateRound(
		ctx context.Context, id string, updateFn func(r *Round) (*Round, error),
	) error
}

type VtxoRepository interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) error
	SpendVtxos(ctx context.Context, vtxos []VtxoKey) error
	GetVtxos(ctx context.Context, vtxos []VtxoKey) ([]Vtxo, error)
}
