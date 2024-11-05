package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/infrastructure/db/sqlite/sqlc/queries"
)

type noteRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewNoteRepository(config ...interface{}) (domain.NoteRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open note repository: invalid config, expected db at 0")
	}

	return &noteRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (n *noteRepository) Close() {
	_ = n.db.Close()
}

func (n *noteRepository) Add(ctx context.Context, id uint64) error {
	return n.querier.InsertNote(ctx, int64(id))
}

func (n *noteRepository) Contains(ctx context.Context, id uint64) (bool, error) {
	contains, err := n.querier.ContainsNote(ctx, int64(id))
	if err != nil {
		return false, err
	}
	return contains == 1, nil
}
