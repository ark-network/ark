package ports

import "github.com/ark-network/ark/internal/core/domain"

type RepoManager interface {
	Events() domain.RoundEventRepository
	Rounds() domain.RoundRepository
}
