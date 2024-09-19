package sqlitestore

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/golang-migrate/migrate/v4"
	sqlitemigrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	log "github.com/sirupsen/logrus"
)

const (
	sqliteDbFile = "appdata.sqlite.db"
	driverName   = "sqlite"
)

type appDataRepository struct {
	db *sql.DB

	transactionRepo store.TransactionRepository
	vtxoRepo        store.VtxoRepository
}

func NewAppDataRepository(
	baseDir string, migrationPath string,
) (store.AppDataStore, error) {
	dbFile := filepath.Join(baseDir, sqliteDbFile)
	db, err := openDb(dbFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %s", err)
	}

	driver, err := sqlitemigrate.WithInstance(db, &sqlitemigrate.Config{})
	if err != nil {
		return nil, err
	}

	m, err := migrate.NewWithDatabaseInstance(
		migrationPath,
		"ark-sdk.db",
		driver,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create migration instance: %s", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return nil, fmt.Errorf("failed to run migrations: %s", err)
	}

	return &appDataRepository{
		db:              db,
		transactionRepo: NewTransactionRepository(db),
		vtxoRepo:        NewVtxoRepository(db),
	}, nil
}

func (a *appDataRepository) TransactionRepository() store.TransactionRepository {
	return a.transactionRepo
}

func (a *appDataRepository) VtxoRepository() store.VtxoRepository {
	return a.vtxoRepo
}

func (a *appDataRepository) Stop() {
	a.transactionRepo.Stop()

	if err := a.db.Close(); err != nil {
		log.Warnf("failed to close app data store: %v", err)
	}
}

func openDb(dbPath string) (*sql.DB, error) {
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

	db.SetMaxOpenConns(1)

	return db, nil
}
