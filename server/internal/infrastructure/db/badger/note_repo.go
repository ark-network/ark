package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const noteStoreDir = "notes"

type noteRepository struct {
	store *badgerhold.Store
	lock  *sync.Mutex
}

type note struct {
	ID uint64
}

func NewNoteRepository(config ...interface{}) (domain.NoteRepository, error) {
	if len(config) != 2 {
		return nil, fmt.Errorf("invalid config")
	}
	baseDir, ok := config[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid base directory")
	}

	var logger badger.Logger
	if config[1] != nil {
		logger, ok = config[1].(badger.Logger)
		if !ok {
			return nil, fmt.Errorf("invalid logger")
		}
	}

	var dir string
	if len(baseDir) > 0 {
		dir = filepath.Join(baseDir, noteStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open note store: %s", err)
	}
	lock := &sync.Mutex{}
	repo := &noteRepository{store, lock}
	return repo, nil
}

func (n *noteRepository) Close() {
	n.store.Close()
}

func (n *noteRepository) Add(ctx context.Context, id uint64) error {
	n.lock.Lock()
	defer n.lock.Unlock()

	if err := n.store.Insert(id, note{ID: id}); err != nil {
		if errors.Is(err, badger.ErrConflict) {
			attempts := 1
			for errors.Is(err, badger.ErrConflict) && attempts <= maxRetries {
				time.Sleep(100 * time.Millisecond)
				err = n.store.Insert(id, note{ID: id})
				attempts++
			}
		}
		return err
	}
	return nil
}

func (n *noteRepository) Contains(ctx context.Context, id uint64) (bool, error) {
	n.lock.Lock()
	defer n.lock.Unlock()

	var v note
	err := n.store.Get(id, &v)
	if err != nil {
		if errors.Is(err, badgerhold.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
