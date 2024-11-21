package domain

import "context"

type Entity struct {
	NostrRecipient string
}

type EntityRepository interface {
	Add(ctx context.Context, data Entity, vtxoKeys []VtxoKey) error
	Get(ctx context.Context, vtxoKey VtxoKey) ([]Entity, error)
	Delete(ctx context.Context, vtxoKeys []VtxoKey) error
}
