package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/infrastructure/db/sqlite/sqlc/queries"
)

type vtxoRepository struct {
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

	return &vtxoRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (v *vtxoRepository) Close() {
	_ = v.db.Close()
}

func (v *vtxoRepository) AddVtxos(ctx context.Context, vtxos []domain.Vtxo) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for i := range vtxos {
			vtxo := vtxos[i]

			if err := querierWithTx.UpsertVtxo(
				ctx, queries.UpsertVtxoParams{
					Txid:      vtxo.Txid,
					Vout:      int64(vtxo.VOut),
					Pubkey:    vtxo.PubKey,
					Amount:    int64(vtxo.Amount),
					RoundTx:   vtxo.RoundTxid,
					SpentBy:   vtxo.SpentBy,
					Spent:     vtxo.Spent,
					Redeemed:  vtxo.Redeemed,
					Swept:     vtxo.Swept,
					ExpireAt:  vtxo.ExpireAt,
					CreatedAt: vtxo.CreatedAt,
					RedeemTx:  sql.NullString{String: vtxo.RedeemTx, Valid: true},
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vtxoRepository) GetAllSweepableVtxos(ctx context.Context) ([]domain.Vtxo, error) {
	res, err := v.querier.SelectSweepableVtxos(ctx)
	if err != nil {
		return nil, err
	}

	rows := make([]queries.Vtxo, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.Vtxo)
	}
	return readRows(rows)
}

func (v *vtxoRepository) GetAllNonRedeemedVtxos(ctx context.Context, pubkey string) ([]domain.Vtxo, []domain.Vtxo, error) {
	withPubkey := len(pubkey) > 0

	var rows []queries.Vtxo
	if withPubkey {
		res, err := v.querier.SelectNotRedeemedVtxosWithPubkey(ctx, pubkey)
		if err != nil {
			return nil, nil, err
		}
		rows = make([]queries.Vtxo, 0, len(res))
		for _, row := range res {
			rows = append(rows, row.Vtxo)
		}
	} else {
		res, err := v.querier.SelectNotRedeemedVtxos(ctx)
		if err != nil {
			return nil, nil, err
		}
		rows = make([]queries.Vtxo, 0, len(res))
		for _, row := range res {
			rows = append(rows, row.Vtxo)
		}
	}

	vtxos, err := readRows(rows)
	if err != nil {
		return nil, nil, err
	}

	unspentVtxos := make([]domain.Vtxo, 0)
	spentVtxos := make([]domain.Vtxo, 0)

	for _, vtxo := range vtxos {
		if vtxo.Spent || vtxo.Swept {
			spentVtxos = append(spentVtxos, vtxo)
		} else {
			unspentVtxos = append(unspentVtxos, vtxo)
		}
	}

	return unspentVtxos, spentVtxos, nil
}

func (v *vtxoRepository) GetVtxos(ctx context.Context, outpoints []domain.VtxoKey) ([]domain.Vtxo, error) {
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

		result, err := readRows([]queries.Vtxo{res.Vtxo})
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

func (v *vtxoRepository) GetAll(ctx context.Context) ([]domain.Vtxo, error) {
	res, err := v.querier.SelectAllVtxos(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]queries.Vtxo, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.Vtxo)
	}

	return readRows(rows)
}

func (v *vtxoRepository) GetVtxosForRound(ctx context.Context, txid string) ([]domain.Vtxo, error) {
	res, err := v.querier.SelectVtxosByRoundTxid(ctx, txid)
	if err != nil {
		return nil, err
	}
	rows := make([]queries.Vtxo, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.Vtxo)
	}

	return readRows(rows)
}

func (v *vtxoRepository) GetSpendableVtxosWithPubKey(ctx context.Context, pubkey string) ([]domain.Vtxo, error) {
	rows, err := v.querier.GetSpendableVtxosWithPubKey(ctx, pubkey)
	if err != nil {
		return nil, err
	}

	vtxos := make([]domain.Vtxo, 0, len(rows))
	for _, row := range rows {
		vtxos = append(vtxos, domain.Vtxo{
			VtxoKey: domain.VtxoKey{
				Txid: row.Txid,
				VOut: uint32(row.Vout),
			},
			Amount:    uint64(row.Amount),
			PubKey:    row.Pubkey,
			RoundTxid: row.RoundTx,
			SpentBy:   row.SpentBy,
			Spent:     row.Spent,
			Redeemed:  row.Redeemed,
			Swept:     row.Swept,
			ExpireAt:  row.ExpireAt,
			RedeemTx:  row.RedeemTx.String,
			CreatedAt: row.CreatedAt,
		})
	}

	return vtxos, nil
}

func (v *vtxoRepository) RedeemVtxos(ctx context.Context, vtxos []domain.VtxoKey) error {
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

func (v *vtxoRepository) SpendVtxos(ctx context.Context, vtxos []domain.VtxoKey, txid string) error {
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

func (v *vtxoRepository) SweepVtxos(ctx context.Context, vtxos []domain.VtxoKey) error {
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

func (v *vtxoRepository) UpdateExpireAt(ctx context.Context, vtxos []domain.VtxoKey, expireAt int64) error {
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

func (v *vtxoRepository) GetAllVtxosWithPubKey(
	ctx context.Context, pubkey string,
) ([]domain.Vtxo, []domain.Vtxo, error) {
	res, err := v.querier.SelectVtxosWithPubkey(ctx, pubkey)
	if err != nil {
		return nil, nil, err
	}
	rows := make([]queries.Vtxo, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.Vtxo)
	}

	vtxos, err := readRows(rows)
	if err != nil {
		return nil, nil, err
	}

	unspentVtxos := make([]domain.Vtxo, 0)
	spentVtxos := make([]domain.Vtxo, 0)

	for _, vtxo := range vtxos {
		if vtxo.Spent || vtxo.Swept {
			spentVtxos = append(spentVtxos, vtxo)
		} else {
			unspentVtxos = append(unspentVtxos, vtxo)
		}
	}

	return unspentVtxos, spentVtxos, nil
}

func rowToVtxo(row queries.Vtxo) domain.Vtxo {
	return domain.Vtxo{
		VtxoKey: domain.VtxoKey{
			Txid: row.Txid,
			VOut: uint32(row.Vout),
		},
		Amount:    uint64(row.Amount),
		PubKey:    row.Pubkey,
		RoundTxid: row.RoundTx,
		SpentBy:   row.SpentBy,
		Spent:     row.Spent,
		Redeemed:  row.Redeemed,
		Swept:     row.Swept,
		ExpireAt:  row.ExpireAt,
		RedeemTx:  row.RedeemTx.String,
		CreatedAt: row.CreatedAt,
	}
}

func readRows(rows []queries.Vtxo) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0, len(rows))
	for _, vtxo := range rows {
		vtxos = append(vtxos, rowToVtxo(vtxo))
	}

	return vtxos, nil
}
