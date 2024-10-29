package domain

import "context"

// Metadata holds metadata associated with a VTXO
type Metadata struct {
	NostrRecipient string
}

type MetadataRepository interface {
	AddOrUpdate(ctx context.Context, data Metadata, vtxoKeys []VtxoKey) error
	Get(ctx context.Context, vtxoKey VtxoKey) (*Metadata, error)
	Delete(ctx context.Context, vtxoKeys []VtxoKey) error
}
