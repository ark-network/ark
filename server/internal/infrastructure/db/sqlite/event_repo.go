package sqlitedb

import (
	"context"
	"database/sql"

	"github.com/ark-network/ark/internal/core/domain"
)

type eventRepository struct {
	db *sql.DB
}

func NewRoundEventRepository(dbPath string) (domain.RoundEventRepository, error) {
	return &eventRepository{
		db: db,
	}
}

// Load implements domain.RoundEventRepository.
func (e *eventRepository) Load(ctx context.Context, id string) (*domain.Round, error) {
	panic("unimplemented")
}

// Save implements domain.RoundEventRepository.
func (e *eventRepository) Save(ctx context.Context, id string, events ...domain.RoundEvent) (*domain.Round, error) {
	panic("unimplemented")
}
