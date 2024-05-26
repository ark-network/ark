package sqlitedb

import (
	"context"
	"database/sql"

	"github.com/ark-network/ark/internal/core/domain"
)

type paymentRow struct {
	id 			string
	

type roundRow struct {
	id                string
	startingTimestamp int64
	endingTimestamp   int64
	ended             bool
	failed            bool
	stageCode         domain.RoundStage
	txid              string
	payments []
}

type roundRepository struct {
	db *sql.DB
}

func NewRoundRepository(dbPath string) (domain.RoundRepository, error) {
	db, err := openDB(dbPath)
	if err != nil {
		return nil, err
	}

	return &roundRepository{
		db: db,
	}, nil
}

// AddOrUpdateRound implements domain.RoundRepository.
func (r *roundRepository) AddOrUpdateRound(ctx context.Context, round domain.Round) error {
	panic("unimplemented")
}

// GetCurrentRound implements domain.RoundRepository.
func (r *roundRepository) GetCurrentRound(ctx context.Context) (*domain.Round, error) {
	panic("unimplemented")
}

// GetRoundWithId implements domain.RoundRepository.
func (r *roundRepository) GetRoundWithId(ctx context.Context, id string) (*domain.Round, error) {
	panic("unimplemented")
}

// GetRoundWithTxid implements domain.RoundRepository.
func (r *roundRepository) GetRoundWithTxid(ctx context.Context, txid string) (*domain.Round, error) {
	panic("unimplemented")
}

// GetSweepableRounds implements domain.RoundRepository.
func (r *roundRepository) GetSweepableRounds(ctx context.Context) ([]domain.Round, error) {
	panic("unimplemented")
}
