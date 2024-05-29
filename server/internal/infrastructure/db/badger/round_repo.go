package badgerdb

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/ark-network/ark/internal/core/domain"
	dbtypes "github.com/ark-network/ark/internal/infrastructure/db/types"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const roundStoreDir = "rounds"

type roundRepository struct {
	store *badgerhold.Store
}

func NewRoundRepository(config ...interface{}) (dbtypes.RoundStore, error) {
	if len(config) != 2 {
		return nil, fmt.Errorf("invalid config")
	}
	baseDir, ok := config[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid base directory")
	}
	var logger badger.Logger
	if config[1] != nil {
		logger, ok = config[1].(badger.Logger)
		if !ok {
			return nil, fmt.Errorf("invalid logger")
		}
	}

	var dir string
	if len(baseDir) > 0 {
		dir = filepath.Join(baseDir, roundStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open round events store: %s", err)
	}

	return &roundRepository{store}, nil
}

func (r *roundRepository) AddOrUpdateRound(
	ctx context.Context, round domain.Round,
) error {
	return r.addOrUpdateRound(ctx, round)
}

func (r *roundRepository) GetCurrentRound(
	ctx context.Context,
) (*domain.Round, error) {
	query := badgerhold.Where("Stage.Ended").Eq(false).And("Stage.Failed").Eq(false)
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(rounds) <= 0 {
		return nil, fmt.Errorf("ongoing round not found")
	}
	return &rounds[0], nil
}

func (r *roundRepository) GetRoundWithId(
	ctx context.Context, id string,
) (*domain.Round, error) {
	query := badgerhold.Where("Id").Eq(id)
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(rounds) <= 0 {
		return nil, fmt.Errorf("round with id %s not found", id)
	}
	round := &rounds[0]
	return round, nil
}

func (r *roundRepository) GetRoundWithTxid(
	ctx context.Context, txid string,
) (*domain.Round, error) {
	query := badgerhold.Where("Txid").Eq(txid)
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(rounds) <= 0 {
		return nil, fmt.Errorf("round with txid %s not found", txid)
	}
	round := &rounds[0]
	return round, nil
}

func (r *roundRepository) GetSweepableRounds(
	ctx context.Context,
) ([]domain.Round, error) {
	query := badgerhold.Where("Stage.Code").Eq(domain.FinalizationStage).
		And("Stage.Ended").Eq(true).And("Swept").Eq(false)
	return r.findRound(ctx, query)
}

func (r *roundRepository) GetSweptRounds(ctx context.Context) ([]domain.Round, error) {
	query := badgerhold.Where("Stage.Code").Eq(domain.FinalizationStage).
		And("Stage.Ended").Eq(true).And("Swept").Eq(true).And("ConnectorAddress").Ne("")
	return r.findRound(ctx, query)
}

func (r *roundRepository) GetRoundsIds(ctx context.Context, startedAfter int64, startedBefore int64) ([]string, error) {
	query := badgerhold.Where("Stage.Ended").Eq(true)

	if startedAfter > 0 {
		query = query.And("StartingTimestamp").Gt(startedAfter)
	}

	if startedBefore > 0 {
		query = query.And("StartingTimestamp").Lt(startedBefore)
	}

	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(rounds))
	for _, round := range rounds {
		ids = append(ids, round.Id)
	}

	return ids, nil
}

func (r *roundRepository) Close() {
	r.store.Close()
}

func (r *roundRepository) findRound(
	ctx context.Context, query *badgerhold.Query,
) ([]domain.Round, error) {
	var rounds []domain.Round
	var err error

	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxFind(tx, &rounds, query)
	} else {
		err = r.store.Find(&rounds, query)
	}

	return rounds, err
}

func (r *roundRepository) addOrUpdateRound(
	ctx context.Context, round domain.Round,
) (err error) {
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxUpsert(tx, round.Id, round)
	} else {
		err = r.store.Upsert(round.Id, round)
	}
	return
}
