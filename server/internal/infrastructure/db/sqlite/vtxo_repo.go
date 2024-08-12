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
			var redeemTx string
			if vtxo.AsyncPayment != nil {
				redeemTx = vtxo.AsyncPayment.RedeemTx
			}
			if err := querierWithTx.UpsertVtxo(
				ctx, queries.UpsertVtxoParams{
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
					RedeemTx: sql.NullString{String: redeemTx, Valid: true},
				},
			); err != nil {
				return err
			}

			if vtxo.AsyncPayment != nil {
				for i, tx := range vtxo.AsyncPayment.UnconditionalForfeitTxs {
					if err := querierWithTx.UpsertUnconditionalForfeitTx(ctx, queries.UpsertUnconditionalForfeitTxParams{
						Tx:       tx,
						VtxoTxid: vtxo.Txid,
						VtxoVout: int64(vtxo.VOut),
						Position: int64(i),
					}); err != nil {
						return err
					}
				}
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vxtoRepository) GetAllSweepableVtxos(ctx context.Context) ([]domain.Vtxo, error) {
	res, err := v.querier.SelectSweepableVtxos(ctx)
	if err != nil {
		return nil, err
	}

	rows := make([]vtxoWithUnconditionalForfeitTxs, 0, len(res))
	for _, row := range res {
		rows = append(rows, vtxoWithUnconditionalForfeitTxs{
			vtxo: row.Vtxo,
			tx:   row.UncondForfeitTxVw,
		})
	}
	return readRows(rows)
}

func (v *vxtoRepository) GetAllVtxos(ctx context.Context, pubkey string) ([]domain.Vtxo, []domain.Vtxo, error) {
	withPubkey := len(pubkey) > 0

	var rows []vtxoWithUnconditionalForfeitTxs
	if withPubkey {
		res, err := v.querier.SelectNotRedeemedVtxosWithPubkey(ctx, pubkey)
		if err != nil {
			return nil, nil, err
		}
		rows = make([]vtxoWithUnconditionalForfeitTxs, 0, len(res))
		for _, row := range res {
			rows = append(rows, vtxoWithUnconditionalForfeitTxs{
				vtxo: row.Vtxo,
				tx:   row.UncondForfeitTxVw,
			})
		}
	} else {
		res, err := v.querier.SelectNotRedeemedVtxos(ctx)
		if err != nil {
			return nil, nil, err
		}
		rows = make([]vtxoWithUnconditionalForfeitTxs, 0, len(res))
		for _, row := range res {
			rows = append(rows, vtxoWithUnconditionalForfeitTxs{
				vtxo: row.Vtxo,
				tx:   row.UncondForfeitTxVw,
			})
		}
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
		res, err := v.querier.SelectVtxoByOutpoint(
			ctx,
			queries.SelectVtxoByOutpointParams{
				Txid: o.Txid,
				Vout: int64(o.VOut),
			},
		)
		if err != nil {
			return nil, err
		}

		result, err := readRows([]vtxoWithUnconditionalForfeitTxs{
			{
				vtxo: res.Vtxo,
				tx:   res.UncondForfeitTxVw,
			},
		})
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
	res, err := v.querier.SelectVtxosByPoolTxid(ctx, txid)
	if err != nil {
		return nil, err
	}
	rows := make([]vtxoWithUnconditionalForfeitTxs, 0, len(res))
	for _, row := range res {
		rows = append(rows, vtxoWithUnconditionalForfeitTxs{
			vtxo: row.Vtxo,
			tx:   row.UncondForfeitTxVw,
		})
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

func rowToVtxo(row queries.Vtxo, uncondForfeitTxs []queries.UncondForfeitTxVw) domain.Vtxo {
	var asyncPayment *domain.AsyncPaymentTxs
	if row.RedeemTx.Valid && len(uncondForfeitTxs) > 0 {
		txs := make([]string, len(uncondForfeitTxs))
		for _, tx := range uncondForfeitTxs {
			txs[tx.Position.Int64] = tx.Tx.String
		}
		asyncPayment = &domain.AsyncPaymentTxs{
			RedeemTx:                row.RedeemTx.String,
			UnconditionalForfeitTxs: txs,
		}
	}
	return domain.Vtxo{
		VtxoKey: domain.VtxoKey{
			Txid: row.Txid,
			VOut: uint32(row.Vout),
		},
		Receiver: domain.Receiver{
			Pubkey: row.Pubkey,
			Amount: uint64(row.Amount),
		},
		PoolTx:       row.PoolTx,
		SpentBy:      row.SpentBy,
		Spent:        row.Spent,
		Redeemed:     row.Redeemed,
		Swept:        row.Swept,
		ExpireAt:     row.ExpireAt,
		AsyncPayment: asyncPayment,
	}
}

type vtxoWithUnconditionalForfeitTxs struct {
	vtxo queries.Vtxo
	tx   queries.UncondForfeitTxVw
}

func readRows(rows []vtxoWithUnconditionalForfeitTxs) ([]domain.Vtxo, error) {
	uncondForfeitTxsMap := make(map[domain.VtxoKey][]queries.UncondForfeitTxVw)
	for _, row := range rows {
		if !row.vtxo.RedeemTx.Valid {
			continue
		}
		vtxoKey := domain.VtxoKey{
			Txid: row.vtxo.Txid,
			VOut: uint32(row.vtxo.Vout),
		}
		if _, ok := uncondForfeitTxsMap[vtxoKey]; !ok {
			uncondForfeitTxsMap[vtxoKey] = make([]queries.UncondForfeitTxVw, 0)
		}
		if row.tx.Tx.Valid {
			uncondForfeitTxsMap[vtxoKey] = append(
				uncondForfeitTxsMap[vtxoKey], row.tx,
			)
		}
	}
	vtxos := make([]domain.Vtxo, 0, len(rows))
	for _, row := range rows {
		vtxoKey := domain.VtxoKey{
			Txid: row.vtxo.Txid,
			VOut: uint32(row.vtxo.Vout),
		}
		uncondForfeitTxs := uncondForfeitTxsMap[vtxoKey]
		vtxos = append(vtxos, rowToVtxo(row.vtxo, uncondForfeitTxs))
	}

	return vtxos, nil
}
