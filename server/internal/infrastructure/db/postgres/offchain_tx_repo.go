package pgdb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/infrastructure/db/postgres/sqlc/queries"
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
		// Upsert virtual tx (offchain tx)
		// (Assume there is an upsert for the virtual_tx table, pseudo-code)
		// err := querierWithTx.UpsertVirtualTx(...)
		// if err != nil { return err }

		// Upsert checkpoint txs and their order
		for i, commitmentTxid := range offchainTx.CommitmentTxids {
			checkpointTx, ok := offchainTx.CheckpointTxs[commitmentTxid]
			if !ok {
				continue
			}
			err := querierWithTx.UpsertCheckpointTx(ctx, queries.UpsertCheckpointTxParams{
				Txid:                       commitmentTxid,
				Tx:                         checkpointTx,
				CommitmentTxid:             commitmentTxid,
				CommitmentTxExpiryPosition: int32(i),
				VirtualTxid:                offchainTx.VirtualTxid,
			})
			if err != nil {
				return err
			}
		}
		return nil
	}
	return execTx(ctx, v.db, txBody)
}

func (v *offchainTxRepository) GetOffchainTx(ctx context.Context, txid string) (*domain.OffchainTx, error) {
	// Get the virtual tx (offchain tx)
	virtualTx, err := v.querier.SelectVirtualTxWithTxId(ctx, txid)
	if err != nil {
		return nil, err
	}

	// Get checkpoint txs in order
	checkpointTxRows, err := v.querier.SelectCheckpointTxsByVirtualTxId(ctx, txid)
	if err != nil {
		return nil, err
	}
	checkpointTxs := make(map[string]string)
	commitmentTxids := make([]string, 0, len(checkpointTxRows))
	for _, row := range checkpointTxRows {
		checkpointTxs[row.CommitmentTxid] = row.Tx
		commitmentTxids = append(commitmentTxids, row.CommitmentTxid)
	}

	return &domain.OffchainTx{
		VirtualTxid:       virtualTx.VirtualTx.Txid,
		VirtualTx:         virtualTx.VirtualTx.Tx,
		StartingTimestamp: virtualTx.VirtualTx.StartingTimestamp,
		EndingTimestamp:   virtualTx.VirtualTx.EndingTimestamp,
		ExpiryTimestamp:   virtualTx.VirtualTx.ExpiryTimestamp,
		FailReason:        virtualTx.VirtualTx.FailReason.String,
		Stage:             domain.Stage{Code: int(virtualTx.VirtualTx.StageCode)},
		CheckpointTxs:     checkpointTxs,
		CommitmentTxids:   commitmentTxids,
	}, nil
}

func (v *offchainTxRepository) Close() {
	_ = v.db.Close()
}

func rowsToOffchainTxs(rows []queries.SelectVirtualTxWithTxIdRow) []*domain.OffchainTx {

}
