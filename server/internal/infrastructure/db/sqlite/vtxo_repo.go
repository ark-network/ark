package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/infrastructure/db/sqlite/sqlc/queries"
)

type vxtoRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewVtxoRepository(config ...interface{}) (domain.VtxoRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open vtxo repository: invalid config")
	}

	return &vxtoRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (v *vxtoRepository) Close() {
	_ = v.db.Close()
}

func (v *vxtoRepository) AddVtxos(ctx context.Context, vtxos []domain.Vtxo) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for i := range vtxos {
			vtxo := vtxos[i]
			if err := querierWithTx.UpsertVtxo(
				ctx,
				queries.UpsertVtxoParams{
					Txid:     vtxo.Txid,
					Vout:     int64(vtxo.VOut),
					Pubkey:   vtxo.Pubkey,
					Amount:   int64(vtxo.Amount),
					PoolTx:   vtxo.PoolTx,
					SpentBy:  vtxo.SpentBy,
					Spent:    vtxo.Spent,
					Redeemed: vtxo.Redeemed,
					Swept:    vtxo.Swept,
					ExpireAt: vtxo.ExpireAt,
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vxtoRepository) GetAllSweepableVtxos(ctx context.Context) ([]domain.Vtxo, error) {
	rows, err := v.querier.SelectSweepableVtxos(ctx)
	if err != nil {
		return nil, err
	}

	return readRows(rows)
}

func (v *vxtoRepository) GetAllVtxos(ctx context.Context, pubkey string) ([]domain.Vtxo, []domain.Vtxo, error) {
	withPubkey := len(pubkey) > 0

	var rows []queries.Vtxo
	var err error

	if withPubkey {
		rows, err = v.querier.SelectNotRedeemedVtxosWithPubkey(ctx, pubkey)
	} else {
		rows, err = v.querier.SelectNotRedeemedVtxos(ctx)
	}
	if err != nil {
		return nil, nil, err
	}

	vtxos, err := readRows(rows)
	if err != nil {
		return nil, nil, err
	}

	unspentVtxos := make([]domain.Vtxo, 0)
	spentVtxos := make([]domain.Vtxo, 0)

	for _, vtxo := range vtxos {
		if vtxo.Spent {
			spentVtxos = append(spentVtxos, vtxo)
		} else {
			unspentVtxos = append(unspentVtxos, vtxo)
		}
	}

	return unspentVtxos, spentVtxos, nil
}

func (v *vxtoRepository) GetVtxos(ctx context.Context, outpoints []domain.VtxoKey) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0, len(outpoints))
	for _, o := range outpoints {
		vtxo, err := v.querier.SelectVtxoByOutpoint(
			ctx,
			queries.SelectVtxoByOutpointParams{
				Txid: o.Txid,
				Vout: int64(o.VOut),
			},
		)
		if err != nil {
			return nil, err
		}

		result, err := readRows([]queries.Vtxo{vtxo})
		if err != nil {
			return nil, err
		}

		if len(result) == 0 {
			return nil, fmt.Errorf("vtxo not found")
		}

		vtxos = append(vtxos, result[0])
	}

	return vtxos, nil
}

func (v *vxtoRepository) GetVtxosForRound(ctx context.Context, txid string) ([]domain.Vtxo, error) {
	rows, err := v.querier.SelectVtxosByPoolTxid(ctx, txid)
	if err != nil {
		return nil, err
	}

	return readRows(rows)
}

func (v *vxtoRepository) RedeemVtxos(ctx context.Context, vtxos []domain.VtxoKey) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			if err := querierWithTx.MarkVtxoAsRedeemed(
				ctx,
				queries.MarkVtxoAsRedeemedParams{
					Txid: vtxo.Txid,
					Vout: int64(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vxtoRepository) SpendVtxos(ctx context.Context, vtxos []domain.VtxoKey, txid string) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			if err := querierWithTx.MarkVtxoAsSpent(
				ctx,
				queries.MarkVtxoAsSpentParams{
					SpentBy: txid,
					Txid:    vtxo.Txid,
					Vout:    int64(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vxtoRepository) SweepVtxos(ctx context.Context, vtxos []domain.VtxoKey) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			if err := querierWithTx.MarkVtxoAsSwept(
				ctx,
				queries.MarkVtxoAsSweptParams{
					Txid: vtxo.Txid,
					Vout: int64(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vxtoRepository) UpdateExpireAt(ctx context.Context, vtxos []domain.VtxoKey, expireAt int64) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			if err := querierWithTx.UpdateVtxoExpireAt(
				ctx,
				queries.UpdateVtxoExpireAtParams{
					ExpireAt: expireAt,
					Txid:     vtxo.Txid,
					Vout:     int64(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func rowToVtxo(row queries.Vtxo) domain.Vtxo {
	return domain.Vtxo{
		VtxoKey: domain.VtxoKey{
			Txid: row.Txid,
			VOut: uint32(row.Vout),
		},
		Receiver: domain.Receiver{
			Pubkey: row.Pubkey,
			Amount: uint64(row.Amount),
		},
		PoolTx:   row.PoolTx,
		SpentBy:  row.SpentBy,
		Spent:    row.Spent,
		Redeemed: row.Redeemed,
		Swept:    row.Swept,
		ExpireAt: row.ExpireAt,
	}
}

func readRows(rows []queries.Vtxo) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0, len(rows))
	for _, v := range rows {
		vtxos = append(vtxos, rowToVtxo(v))
	}

	return vtxos, nil
}
