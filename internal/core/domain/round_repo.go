package domain

import "context"

type RoundEventRepository interface {
	Save(ctx context.Context, events ...RoundEvent) error
	Load(ctx context.Context, id string) (*Round, error)
}

type RoundRepository interface {
	AddRound(ctx context.Context, round *Round) error
	GetCurrentRound(ctx context.Context) (*Round, error)
	GetRoundWithId(ctx, id string) (*Round, error)
	GetRoundWithTxid(ctx, txid string) (*Round, error)
}
