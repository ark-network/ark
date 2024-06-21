package btcwallet

import (
	"path/filepath"
	"time"

	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
)

const (
	dbDriver = "bdb"
	dbFile   = "wallet.db"
)

var (
	dbTimeout = 10 * time.Second
)

func openOrCreateDB(datadir string) (walletdb.DB, error) {
	filepath := filepath.Join(datadir, dbFile)

	db, err := walletdb.Open(
		dbDriver,
		filepath,
		true,
		dbTimeout,
	)
	if err != nil {
		if err == walletdb.ErrDbDoesNotExist {
			return walletdb.Create(
				dbDriver,
				filepath,
				true,
				dbTimeout,
			)
		}
		return nil, err
	}

	return db, nil
}
