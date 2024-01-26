package badgerdb

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

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

func (r *roundRepository) GetExpiredOutputs(
	ctx context.Context,
) ([]domain.ExpiredRound, error) {
	nowTimestamp := time.Now().Unix()
	query := badgerhold.Where("Stage.Ended").Eq(true).And("Stage.Failed").Eq(false).And("SharedOutputs").MatchFunc(func(val *badgerhold.RecordAccess) (bool, error) {
		sharedOutputs, ok := val.Field().([]domain.SharedOutput)
		if !ok {
			return false, fmt.Errorf("invalid shared outputs")
		}

		for _, sharedOutput := range sharedOutputs {
			if !sharedOutput.Spent && len(sharedOutput.SweepTxid) == 0 && sharedOutput.ExpirationTimestamp < nowTimestamp {
				return true, nil
			}
		}
		return false, nil
	})
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}

	expiredRounds := make([]domain.ExpiredRound, 0, len(rounds))

	for _, round := range rounds {
		indexes := make([]int, 0, len(round.SharedOutputs))
		for i, sharedOutput := range round.SharedOutputs {
			if len(sharedOutput.SweepTxid) == 0 && sharedOutput.ExpirationTimestamp <= nowTimestamp {
				indexes = append(indexes, i)
			}
		}
		expiredRounds = append(expiredRounds, domain.ExpiredRound{
			Round:          round,
			ExpiredOutputs: indexes,
		})
	}

	return expiredRounds, nil
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
