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

const vtxoStoreDir = "vtxos"

type vtxoRepository struct {
	store *badgerhold.Store
}

func NewVtxoRepository(config ...interface{}) (dbtypes.VtxoStore, error) {
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
	ctx context.Context, vtxoKeys []domain.VtxoKey,
) error {
	for _, vtxoKey := range vtxoKeys {
		if err := r.spendVtxo(ctx, vtxoKey); err != nil {
			return err
		}
	}
	return nil
}

func (r *vtxoRepository) RedeemVtxos(
	ctx context.Context, vtxoKeys []domain.VtxoKey,
) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0, len(vtxoKeys))
	for _, vtxoKey := range vtxoKeys {
		vtxo, err := r.redeemVtxo(ctx, vtxoKey)
		if err != nil {
			return nil, err
		}
		if vtxo != nil {
			vtxos = append(vtxos, *vtxo)
		}
	}
	return vtxos, nil
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

func (r *vtxoRepository) GetSpendableVtxosWithPubkey(
	ctx context.Context, pubkey string,
) ([]domain.Vtxo, error) {
	query := badgerhold.Where("Pubkey").Eq(pubkey).
		And("Spent").Eq(false).And("Redeemed").Eq(false)
	return r.findVtxos(ctx, query)
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

func (r *vtxoRepository) spendVtxo(ctx context.Context, vtxoKey domain.VtxoKey) error {
	vtxo, err := r.getVtxo(ctx, vtxoKey)
	if err != nil {
		return err
	}
	if vtxo.Spent {
		return nil
	}

	vtxo.Spent = true
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
		return nil, err
	}
	if vtxo.Redeemed {
		return nil, nil
	}

	vtxo.Redeemed = true
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
	var vtxos []domain.Vtxo
	var err error

	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxFind(tx, &vtxos, query)
	} else {
		err = r.store.Find(&vtxos, query)
	}

	return vtxos, err
}
