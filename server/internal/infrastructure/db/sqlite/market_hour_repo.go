package sqlitedb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/infrastructure/db/sqlite/sqlc/queries"
)

type marketHourRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewMarketHourRepository(config ...interface{}) (domain.MarketHourRepo, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open market hour repository: invalid config, expected db at 0")
	}

	return &marketHourRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (r *marketHourRepository) Get(ctx context.Context) (*domain.MarketHour, error) {
	marketHour, err := r.querier.GetLatestMarketHour(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get market hour: %w", err)
	}

	return &domain.MarketHour{
		ID:              marketHour.ID,
		FirstMarketHour: marketHour.FirstMarketHour,
		Period:          marketHour.Period,
		RoundLifetime:   marketHour.RoundLifetime,
		CreatedAt:       marketHour.CreatedAt,
	}, nil
}

func (r *marketHourRepository) Save(ctx context.Context, marketHour *domain.MarketHour) error {
	result, err := r.querier.SaveMarketHour(ctx, queries.SaveMarketHourParams{
		FirstMarketHour: marketHour.FirstMarketHour,
		Period:          marketHour.Period,
		RoundLifetime:   marketHour.RoundLifetime,
		CreatedAt:       time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("failed to save market hour: %w", err)
	}

	marketHour.ID = result.ID
	marketHour.CreatedAt = result.CreatedAt
	return nil
}

func (r *marketHourRepository) Close() {
	_ = r.db.Close()
}
