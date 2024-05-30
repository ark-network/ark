package sqlitedb

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

const (
	driverName = "sqlite"
)

func OpenDB(dbPath string) (*sql.DB, error) {
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
	return db, nil
}
