package sqlitedb

import (
	"context"
	"database/sql"

	"github.com/ark-network/ark/internal/core/domain"
)

type eventRepository struct {
	db *sql.DB
}

func NewRoundEventRepository(db *sql.DB) (domain.RoundEventRepository, error) {
	return &eventRepository{
		db: db,
	}, nil
}

func (e *eventRepository) Load(ctx context.Context, id string) (*domain.Round, error) {
	return nil, nil
}

func (e *eventRepository) Save(ctx context.Context, id string, events ...domain.RoundEvent) (*domain.Round, error) {
	return nil, nil
}
