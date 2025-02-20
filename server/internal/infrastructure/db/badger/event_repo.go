package badgerdb

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const eventStoreDir = "round-events"

type eventsDTO struct {
	Events [][]byte
}

type eventRepository struct {
	store     *badgerhold.Store
	lock      *sync.Mutex
	chUpdates chan *domain.Round
	handler   func(round *domain.Round)
	done      chan struct{}
	wg        sync.WaitGroup
}

func NewRoundEventRepository(config ...interface{}) (domain.RoundEventRepository, error) {
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
		dir = filepath.Join(baseDir, eventStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open round events store: %s", err)
	}
	repo := &eventRepository{
		store:     store,
		lock:      &sync.Mutex{},
		chUpdates: make(chan *domain.Round),
		done:      make(chan struct{}),
	}
	go repo.listen()
	return repo, nil
}

func (r *eventRepository) Save(
	ctx context.Context, id string, events ...domain.RoundEvent,
) (*domain.Round, error) {
	allEvents, err := r.get(ctx, id)
	if err != nil {
		return nil, err
	}

	allEvents = append(allEvents, events...)
	if err := r.upsert(ctx, id, allEvents); err != nil {
		return nil, err
	}
	r.wg.Add(1)
	go r.publishEvents(allEvents)
	return domain.NewRoundFromEvents(allEvents), nil
}

func (r *eventRepository) Load(
	ctx context.Context, id string,
) (*domain.Round, error) {
	events, err := r.get(ctx, id)
	if err != nil {
		return nil, err
	}
	return domain.NewRoundFromEvents(events), nil
}

func (r *eventRepository) RegisterEventsHandler(
	handler func(round *domain.Round),
) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.handler = handler
}

func (r *eventRepository) Close() {
	close(r.done)
	r.wg.Wait()
	close(r.chUpdates)
	r.store.Close()
}

func (r *eventRepository) get(
	ctx context.Context, id string,
) ([]domain.RoundEvent, error) {
	dto := eventsDTO{}
	var err error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxGet(tx, id, &dto)
	} else {
		err = r.store.Get(id, &dto)
	}
	if err != nil {
		if err == badgerhold.ErrNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get events with id %s: %s", id, err)
	}

	return deserializeEvents(dto.Events)
}

func (r *eventRepository) upsert(
	ctx context.Context, id string, events []domain.RoundEvent,
) error {
	buf, err := serializeEvents(events)
	if err != nil {
		return err
	}
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxUpsert(tx, id, buf)
	} else {
		err = r.store.Upsert(id, buf)
	}
	if err != nil {
		return fmt.Errorf("failed to upsert events with id %s: %s", id, err)
	}
	return nil
}

func (r *eventRepository) listen() {
	for {
		select {
		case <-r.done:
			return
		case round := <-r.chUpdates:
			r.runHandler(round)
		}
	}
}

func (r *eventRepository) publishEvents(events []domain.RoundEvent) {
	defer r.wg.Done()
	round := domain.NewRoundFromEvents(events)
	select {
	case <-r.done:
		return
	case r.chUpdates <- round:
	}
}

func (r *eventRepository) runHandler(round *domain.Round) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.handler == nil {
		return
	}
	r.handler(round)
}
