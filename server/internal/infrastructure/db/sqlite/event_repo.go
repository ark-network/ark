package sqlitedb

import (
	"context"
	"database/sql"

	"github.com/ark-network/ark/internal/core/domain"
)

type eventRow struct {
	id                string
	startingTimestamp int64
	endingTimestamp   int64
}

type eventRepository struct {
	db *sql.DB
}

func NewRoundEventRepository(db *sql.DB) (domain.RoundEventRepository, error) {
	return &eventRepository{
		db: db,
	}, nil
}

// Load implements domain.RoundEventRepository.
func (e *eventRepository) Load(ctx context.Context, id string) (*domain.Round, error) {
	panic("unimplemented")
}

// Save implements domain.RoundEventRepository.
func (e *eventRepository) Save(ctx context.Context, id string, events ...domain.RoundEvent) (*domain.Round, error) {
	panic("unimplemented")
}
