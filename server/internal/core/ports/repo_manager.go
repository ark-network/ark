package ports

import "github.com/ark-network/ark/server/internal/core/domain"

type RepoManager interface {
	Events() domain.EventRepository
	Rounds() domain.RoundRepository
	Vtxos() domain.VtxoRepository
	MarketHourRepo() domain.MarketHourRepo
	OffchainTxs() domain.OffchainTxRepository
	Close()
}
