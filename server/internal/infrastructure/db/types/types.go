package dbtypes

import "github.com/ark-network/ark/internal/core/domain"

type EventStore interface {
	domain.RoundEventRepository
	RegisterEventsHandler(func(*domain.Round))
	Close()
}

type RoundStore interface {
	domain.RoundRepository
	Close()
}

type VtxoStore interface {
	domain.VtxoRepository
	Close()
}
