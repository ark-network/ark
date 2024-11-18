package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/infrastructure/db/sqlite/sqlc/queries"
)

type entityRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewEntityRepository(config ...interface{}) (domain.EntityRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open entity repository: invalid config, expected db at 0")
	}

	return &entityRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (r *entityRepository) Close() {
	_ = r.db.Close()
}

func (r *entityRepository) Add(ctx context.Context, data domain.Entity, vtxoKeys []domain.VtxoKey) error {
	id, err := r.querier.UpsertEntity(ctx, data.NostrRecipient)
	if err != nil {
		return err
	}

	for _, vtxoKey := range vtxoKeys {
		if err := r.querier.UpsertEntityVtxo(ctx, queries.UpsertEntityVtxoParams{
			EntityID: id,
			VtxoTxid: vtxoKey.Txid,
			VtxoVout: int64(vtxoKey.VOut),
		}); err != nil {
			return err
		}
	}

	return nil
}

func (r *entityRepository) Delete(ctx context.Context, vtxoKeys []domain.VtxoKey) error {
	for _, vtxoKey := range vtxoKeys {
		entities, err := r.querier.SelectEntitiesByVtxo(ctx, queries.SelectEntitiesByVtxoParams{
			VtxoTxid: sql.NullString{String: vtxoKey.Txid, Valid: true},
			VtxoVout: sql.NullInt64{Int64: int64(vtxoKey.VOut), Valid: true},
		})
		if err != nil {
			return err
		}

		for _, entity := range entities {
			if err := r.querier.DeleteEntity(ctx, entity.EntityVw.ID); err != nil {
				return err
			}

			if err := r.querier.DeleteEntityVtxo(ctx, entity.EntityVw.ID); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *entityRepository) Get(ctx context.Context, vtxoKey domain.VtxoKey) ([]domain.Entity, error) {
	entities, err := r.querier.SelectEntitiesByVtxo(ctx, queries.SelectEntitiesByVtxoParams{
		VtxoTxid: sql.NullString{String: vtxoKey.Txid, Valid: true},
		VtxoVout: sql.NullInt64{Int64: int64(vtxoKey.VOut), Valid: true},
	})
	if err != nil {
		return nil, err
	}

	if len(entities) == 0 {
		return nil, fmt.Errorf("no entities found")
	}

	result := make([]domain.Entity, 0, len(entities))
	for _, entity := range entities {
		result = append(result, domain.Entity{
			NostrRecipient: entity.EntityVw.NostrRecipient,
		})
	}

	return result, nil
}
