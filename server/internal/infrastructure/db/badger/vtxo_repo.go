package badgerdb

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const vtxoStoreDir = "vtxos"

type vtxoRepository struct {
	store *badgerhold.Store
}

func NewVtxoRepository(config ...interface{}) (domain.VtxoRepository, error) {
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
		dir = filepath.Join(baseDir, vtxoStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open round events store: %s", err)
	}

	return &vtxoRepository{store}, nil
}

func (r *vtxoRepository) AddVtxos(
	ctx context.Context, vtxos []domain.Vtxo,
) error {
	return r.addVtxos(ctx, vtxos)
}

func (r *vtxoRepository) SpendVtxos(
	ctx context.Context, vtxoKeys []domain.VtxoKey, spentBy string,
) error {
	for _, vtxoKey := range vtxoKeys {
		if err := r.spendVtxo(ctx, vtxoKey, spentBy); err != nil {
			return err
		}
	}
	return nil
}

func (r *vtxoRepository) RedeemVtxos(
	ctx context.Context, vtxoKeys []domain.VtxoKey,
) error {
	for _, vtxoKey := range vtxoKeys {
		_, err := r.redeemVtxo(ctx, vtxoKey)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *vtxoRepository) GetVtxos(
	ctx context.Context, vtxoKeys []domain.VtxoKey,
) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0, len(vtxoKeys))
	for _, vtxoKey := range vtxoKeys {
		vtxo, err := r.getVtxo(ctx, vtxoKey)
		if err != nil {
			return nil, err
		}
		vtxos = append(vtxos, *vtxo)
	}
	return vtxos, nil
}

func (r *vtxoRepository) GetVtxosForRound(
	ctx context.Context, txid string,
) ([]domain.Vtxo, error) {
	query := badgerhold.Where("PoolTx").Eq(txid)
	return r.findVtxos(ctx, query)
}

func (r *vtxoRepository) GetAllVtxos(
	ctx context.Context, pubkey string,
) ([]domain.Vtxo, []domain.Vtxo, error) {
	query := badgerhold.Where("Redeemed").Eq(false)
	if len(pubkey) > 0 {
		if len(pubkey) == 66 {
			pubkey = pubkey[2:]
		}

		query = query.And("Descriptor").RegExp(
			regexp.MustCompile(fmt.Sprintf(".*%s.*", pubkey)),
		)
	}
	vtxos, err := r.findVtxos(ctx, query)
	if err != nil {
		return nil, nil, err
	}

	spentVtxos := make([]domain.Vtxo, 0, len(vtxos))
	unspentVtxos := make([]domain.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if vtxo.Spent || vtxo.Swept {
			spentVtxos = append(spentVtxos, vtxo)
		} else {
			unspentVtxos = append(unspentVtxos, vtxo)
		}
	}
	return unspentVtxos, spentVtxos, nil
}

func (r *vtxoRepository) GetAllSweepableVtxos(ctx context.Context) ([]domain.Vtxo, error) {
	query := badgerhold.Where("Redeemed").Eq(false).And("Swept").Eq(false)
	return r.findVtxos(ctx, query)
}

func (r *vtxoRepository) SweepVtxos(
	ctx context.Context, vtxoKeys []domain.VtxoKey,
) error {
	for _, vtxoKey := range vtxoKeys {
		if err := r.sweepVtxo(ctx, vtxoKey); err != nil {
			return err
		}
	}
	return nil
}

func (r *vtxoRepository) UpdateExpireAt(ctx context.Context, vtxos []domain.VtxoKey, expireAt int64) error {
	tx := r.store.Badger().NewTransaction(true)
	defer tx.Discard()

	for _, vtxo := range vtxos {
		vtxo, err := r.getVtxo(ctx, vtxo)
		if err != nil {
			return err
		}
		vtxo.ExpireAt = expireAt
		if err := r.store.TxUpdate(tx, vtxo.Hash(), *vtxo); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *vtxoRepository) Close() {
	r.store.Close()
}

func (r *vtxoRepository) addVtxos(
	ctx context.Context, vtxos []domain.Vtxo,
) (err error) {
	for _, vtxo := range vtxos {
		vtxoKey := vtxo.VtxoKey.Hash()
		if ctx.Value("tx") != nil {
			tx := ctx.Value("tx").(*badger.Txn)
			err = r.store.TxInsert(tx, vtxoKey, vtxo)
		} else {
			err = r.store.Insert(vtxoKey, vtxo)
		}
	}
	if err != nil && err == badgerhold.ErrKeyExists {
		err = nil
	}
	return
}

func (r *vtxoRepository) getVtxo(
	ctx context.Context, vtxoKey domain.VtxoKey,
) (*domain.Vtxo, error) {
	var vtxo domain.Vtxo
	var err error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxGet(tx, vtxoKey.Hash(), &vtxo)
	} else {
		err = r.store.Get(vtxoKey.Hash(), &vtxo)
	}
	if err != nil && err == badgerhold.ErrNotFound {
		return nil, fmt.Errorf("vtxo %s:%d not found", vtxoKey.Txid, vtxoKey.VOut)
	}

	return &vtxo, nil
}

func (r *vtxoRepository) spendVtxo(ctx context.Context, vtxoKey domain.VtxoKey, spendBy string) error {
	vtxo, err := r.getVtxo(ctx, vtxoKey)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil
		}
		return err
	}
	if vtxo.Spent {
		return nil
	}

	vtxo.Spent = true
	vtxo.SpentBy = spendBy
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxUpdate(tx, vtxoKey.Hash(), *vtxo)
	} else {
		err = r.store.Update(vtxoKey.Hash(), *vtxo)
	}
	return err
}

func (r *vtxoRepository) redeemVtxo(ctx context.Context, vtxoKey domain.VtxoKey) (*domain.Vtxo, error) {
	vtxo, err := r.getVtxo(ctx, vtxoKey)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, err
	}
	if vtxo.Redeemed {
		return nil, nil
	}

	vtxo.Redeemed = true
	vtxo.ExpireAt = 0
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxUpdate(tx, vtxoKey.Hash(), *vtxo)
	} else {
		err = r.store.Update(vtxoKey.Hash(), *vtxo)
	}
	if err != nil {
		return nil, err
	}
	return vtxo, nil
}

func (r *vtxoRepository) findVtxos(ctx context.Context, query *badgerhold.Query) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0)
	var err error

	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxFind(tx, &vtxos, query)
	} else {
		err = r.store.Find(&vtxos, query)
	}

	return vtxos, err
}

func (r *vtxoRepository) sweepVtxo(ctx context.Context, vtxoKey domain.VtxoKey) error {
	vtxo, err := r.getVtxo(ctx, vtxoKey)
	if err != nil {
		return err
	}
	if vtxo.Swept {
		return nil
	}

	vtxo.Swept = true
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxUpdate(tx, vtxoKey.Hash(), *vtxo)
	} else {
		err = r.store.Update(vtxoKey.Hash(), *vtxo)
	}
	if err != nil {
		return err
	}
	return nil
}
