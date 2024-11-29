package ports

import "github.com/ark-network/ark/server/internal/core/domain"

type RepoManager interface {
	Events() domain.RoundEventRepository
	Rounds() domain.RoundRepository
	Vtxos() domain.VtxoRepository
	Notes() domain.NoteRepository
	Entities() domain.EntityRepository
	MarketHourRepo() domain.MarketHourRepo
	RegisterEventsHandler(func(*domain.Round))
	Close()
}
