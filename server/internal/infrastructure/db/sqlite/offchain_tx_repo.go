package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/infrastructure/db/sqlite/sqlc/queries"
)

type offchainTxRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewOffchainTxRepository(config ...interface{}) (domain.OffchainTxRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open offchain tx repository: invalid config")
	}

	return &offchainTxRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (v *offchainTxRepository) AddOrUpdateOffchainTx(
	ctx context.Context, offchainTx *domain.OffchainTx,
) error {
	txBody := func(querierWithTx *queries.Queries) error {
		if err := querierWithTx.UpsertOffchainTx(
			ctx, queries.UpsertOffchainTxParams{
				Txid:              offchainTx.VirtualTxid,
				StartingTimestamp: offchainTx.StartingTimestamp,
				EndingTimestamp:   offchainTx.EndingTimestamp,
				ExpiryTimestamp:   offchainTx.ExpiryTimestamp,
				FailReason:        sql.NullString{String: offchainTx.FailReason, Valid: true},
				StageCode:         int64(offchainTx.Stage.Code),
			},
		); err != nil {
			return err
		}

		if offchainTx.VirtualTx != "" {
			if err := querierWithTx.UpsertVirtualTransaction(
				ctx, queries.UpsertVirtualTransactionParams{
					Txid:         offchainTx.VirtualTxid,
					Tx:           offchainTx.VirtualTx,
					Type:         "virtual",
					OffchainTxid: offchainTx.VirtualTxid,
				},
			); err != nil {
				return err
			}
		}

		if len(offchainTx.CheckpointTxs) > 0 {
			for txid, checkpointTx := range offchainTx.CheckpointTxs {
				if err := querierWithTx.UpsertVirtualTransaction(
					ctx, queries.UpsertVirtualTransactionParams{
						Txid:         txid,
						Tx:           checkpointTx,
						Type:         "checkpoint",
						OffchainTxid: offchainTx.VirtualTxid,
					},
				); err != nil {
					return err
				}
			}
		}
		if len(offchainTx.CommitmentTxids) > 0 {
			for i, txid := range offchainTx.CommitmentTxids {
				if err := querierWithTx.UpsertVirtualTransaction(
					ctx, queries.UpsertVirtualTransactionParams{
						Txid:         txid,
						Type:         "commitment",
						OffchainTxid: offchainTx.VirtualTxid,
						Position:     int64(i),
					},
				); err != nil {
					return err
				}
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *offchainTxRepository) GetOffchainTx(ctx context.Context, txid string) (*domain.OffchainTx, error) {
	res, err := v.querier.SelectOffchainTxWithTxId(ctx, txid)
	if err != nil {
		return nil, err
	}

	offchainTxs := rowsToOffchainTxs(res)
	if len(offchainTxs) == 0 {
		return nil, fmt.Errorf("offchain tx not found")
	}

	return offchainTxs[0], nil
}

func (v *offchainTxRepository) Close() {
	_ = v.db.Close()
}

func rowsToOffchainTxs(rows []queries.SelectOffchainTxWithTxIdRow) []*domain.OffchainTx {
	offchainTxs := make(map[string]*domain.OffchainTx)

	for _, v := range rows {
		offchainTx, ok := offchainTxs[v.OffchainTx.Txid]
		if !ok {
			offchainTx = &domain.OffchainTx{
				VirtualTxid:       v.OffchainTx.Txid,
				StartingTimestamp: v.OffchainTx.StartingTimestamp,
				EndingTimestamp:   v.OffchainTx.EndingTimestamp,
				ExpiryTimestamp:   v.OffchainTx.ExpiryTimestamp,
				FailReason:        v.OffchainTx.FailReason.String,
				Stage: domain.Stage{
					Code:   int(v.OffchainTx.StageCode),
					Failed: v.OffchainTx.FailReason.String != "",
				},
				CheckpointTxs:   make(map[string]string),
				CommitmentTxids: make([]string, 0),
			}
		}

		if v.OffchainTxVirtualTxVw.Txid.Valid && v.OffchainTxVirtualTxVw.Type.Valid {
			position := v.OffchainTxVirtualTxVw.Position
			switch v.OffchainTxVirtualTxVw.Type.String {
			case "virtual":
				offchainTx.VirtualTx = v.OffchainTxVirtualTxVw.Tx.String
			case "checkpoint":
				offchainTx.CheckpointTxs[v.OffchainTxVirtualTxVw.Txid.String] = v.OffchainTxVirtualTxVw.Tx.String
			case "commitment":
				offchainTx.CommitmentTxids = extendArray(offchainTx.CommitmentTxids, int(position.Int64))
				offchainTx.CommitmentTxids[position.Int64] = v.OffchainTxVirtualTxVw.Txid.String
			}
		}

		offchainTxs[v.OffchainTx.Txid] = offchainTx
	}

	result := make([]*domain.OffchainTx, 0)
	for _, offchainTx := range offchainTxs {
		result = append(result, offchainTx)
	}
	return result
}
