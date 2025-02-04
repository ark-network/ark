package badgerdb

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const roundStoreDir = "rounds"
const vtxoTreeKeysPrefix = "vtxo_tree_keys"

type roundRepository struct {
	store *badgerhold.Store
}

func NewRoundRepository(config ...interface{}) (domain.RoundRepository, error) {
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

func (r *roundRepository) GetExpiredRoundsTxid(
	ctx context.Context,
) ([]string, error) {
	query := badgerhold.Where("Stage.Code").Eq(domain.FinalizationStage).
		And("Stage.Ended").Eq(true).And("Swept").Eq(false)
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}

	txids := make([]string, 0, len(rounds))
	for _, r := range rounds {
		txids = append(txids, r.Txid)
	}
	return txids, nil
}

func (r *roundRepository) GetSweptRoundsConnectorAddress(
	ctx context.Context,
) ([]string, error) {
	query := badgerhold.Where("Stage.Code").Eq(domain.FinalizationStage).
		And("Stage.Ended").Eq(true).And("Swept").Eq(true).And("ConnectorAddress").Ne("")
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}

	txids := make([]string, 0, len(rounds))
	for _, r := range rounds {
		txids = append(txids, r.Txid)
	}
	return txids, nil
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

func (r *roundRepository) GetVtxoTreeWithTxid(
	ctx context.Context, txid string,
) (tree.VtxoTree, error) {
	round, err := r.GetRoundWithTxid(ctx, txid)
	if err != nil {
		return nil, err
	}
	return round.VtxoTree, nil
}

func (r *roundRepository) Close() {
	r.store.Close()
}

func (r *roundRepository) GetVtxoTreeKeys(ctx context.Context, roundId string) ([]domain.RawKeyPair, error) {
	var keys wrappedVtxoTreeKeys
	var err error

	dbKey := fmt.Sprintf("%s_%s", vtxoTreeKeysPrefix, roundId)

	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxGet(tx, dbKey, &keys)
	} else {
		err = r.store.Get(dbKey, &keys)
	}

	return keys.Keys, err
}

func (r *roundRepository) AddVtxoTreeSecretKey(ctx context.Context, roundId string, seckey, pubkey []byte) error {
	old, err := r.GetVtxoTreeKeys(ctx, roundId)
	if err != nil {
		return err
	}

	new := wrappedVtxoTreeKeys{
		Keys: make([]domain.RawKeyPair, 0, len(old)),
	}
	for _, key := range old {
		if bytes.Equal(key.Pubkey, pubkey) {
			new.Keys = append(new.Keys, domain.RawKeyPair{Pubkey: key.Pubkey, Seckey: seckey})
			continue
		}

		new.Keys = append(new.Keys, key)
	}

	dbKey := fmt.Sprintf("%s_%s", vtxoTreeKeysPrefix, roundId)
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		return r.store.TxUpdate(tx, dbKey, wrappedVtxoTreeKeys{Keys: new.Keys})
	}
	return r.store.Update(dbKey, wrappedVtxoTreeKeys{Keys: new.Keys})
}

func (r *roundRepository) SetVtxoTreePubKeys(ctx context.Context, roundId string, pubkeys [][]byte) error {
	dbKey := fmt.Sprintf("%s_%s", vtxoTreeKeysPrefix, roundId)

	rawKeyPairs := make([]domain.RawKeyPair, 0, len(pubkeys))
	for _, pubkey := range pubkeys {
		rawKeyPairs = append(rawKeyPairs, domain.RawKeyPair{Pubkey: pubkey})
	}

	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		return r.store.TxInsert(tx, dbKey, wrappedVtxoTreeKeys{Keys: rawKeyPairs})
	}
	return r.store.Insert(dbKey, wrappedVtxoTreeKeys{Keys: rawKeyPairs})
}

func (r *roundRepository) GetSweepableEarlyRoundsIds(ctx context.Context) ([]string, error) {
	notSweptRoundsQuery := badgerhold.Where("Stage.Code").Eq(domain.FinalizationStage).
		And("Stage.Ended").Eq(true).And("Swept").Eq(false)
	rounds, err := r.findRound(ctx, notSweptRoundsQuery)
	if err != nil {
		return nil, err
	}

	roundIds := make([]string, 0, len(rounds))

	for _, round := range rounds {
		dbKey := fmt.Sprintf("%s_%s", vtxoTreeKeysPrefix, round.Id)
		var keys wrappedVtxoTreeKeys
		if ctx.Value("tx") != nil {
			tx := ctx.Value("tx").(*badger.Txn)
			err = r.store.TxGet(tx, dbKey, &keys)
		} else {
			err = r.store.Get(dbKey, &keys)
		}

		if err != nil {
			return nil, err
		}

		// if all private keys are set: add to roundIds
		missingSeckey := false
		for _, key := range keys.Keys {
			if key.Seckey == nil {
				missingSeckey = true
				break
			}
		}

		if !missingSeckey {
			roundIds = append(roundIds, round.Id)
		}
	}

	return roundIds, nil
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

type wrappedVtxoTreeKeys struct {
	Keys []domain.RawKeyPair
}
