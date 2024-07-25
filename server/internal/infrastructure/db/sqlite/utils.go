package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ark-network/ark/internal/infrastructure/db/sqlite/sqlc/queries"
	_ "modernc.org/sqlite"
)

const (
	driverName = "sqlite"
)

func OpenDb(dbPath string) (*sql.DB, error) {
	dir := filepath.Dir(dbPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return nil, fmt.Errorf("failed to create directory: %v", err)
		}
	}

	db, err := sql.Open(driverName, dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}

	db.SetMaxOpenConns(1) // prevent concurrent writes

	return db, nil
}

func extendArray[T any](arr []T, position int) []T {
	if arr == nil {
		return make([]T, position+1)
	}

	if len(arr) <= position {
		return append(arr, make([]T, position-len(arr)+1)...)
	}

	return arr
}

func execTx(
	ctx context.Context,
	db *sql.DB,
	txBody func(*queries.Queries) error,
) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}

	querier := queries.New(db)

	defer func() {
		if p := recover(); p != nil {
			rollbackErr := tx.Rollback()
			if rollbackErr != nil {
				err = fmt.Errorf("panic: %v, rollback error: %w", p, rollbackErr)
			}
			panic(p) // Re-throw after rollback
		} else if err != nil {
			rollbackErr := tx.Rollback()
			if rollbackErr != nil {
				err = fmt.Errorf("original error: %v, rollback error: %w", err, rollbackErr)
			}
		}
	}()

	if err = txBody(querier.WithTx(tx)); err != nil {
		return fmt.Errorf("failed to execute transaction: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
