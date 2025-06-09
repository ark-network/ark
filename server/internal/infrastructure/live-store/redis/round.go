package redislivestore

import (
	"context"
	"encoding/json"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/redis/go-redis/v9"
)

const (
	currentRoundKey   = "currentRoundStore:round"
	boardingInputsKey = "boardingInputsStore:numOfInputs"
)

type currentRoundStore struct {
	rdb          *redis.Client
	numOfRetries int
}

type boardingInputsStore struct {
	rdb *redis.Client
}

func NewCurrentRoundStore(rdb *redis.Client, numOfRetries int) ports.CurrentRoundStore {
	return &currentRoundStore{rdb: rdb, numOfRetries: numOfRetries}
}

func (s *currentRoundStore) Upsert(fn func(m *domain.Round) *domain.Round) {
	ctx := context.Background()
	for attempt := 0; attempt < s.numOfRetries; attempt++ {
		err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			var round *domain.Round
			data, err := tx.Get(ctx, currentRoundKey).Bytes()
			if err == nil {
				var r domain.Round
				if err := json.Unmarshal(data, &r); err == nil {
					round = &r
				}
			}
			updated := fn(round)
			val, _ := json.Marshal(updated)
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, currentRoundKey, val, 0)
				return nil
			})
			return err
		})
		if err == nil {
			return
		}
	}
}

func (s *currentRoundStore) Get() *domain.Round {
	ctx := context.Background()
	data, err := s.rdb.Get(ctx, currentRoundKey).Bytes()
	if err != nil {
		return nil
	}
	var round domain.Round
	if err := json.Unmarshal(data, &round); err != nil {
		return nil
	}
	return &round
}

func NewBoardingInputsStore(rdb *redis.Client) ports.BoardingInputsStore {
	return &boardingInputsStore{rdb: rdb}
}

func (b *boardingInputsStore) Set(numOfInputs int) {
	ctx := context.Background()
	b.rdb.Set(ctx, boardingInputsKey, numOfInputs, 0)
}

func (b *boardingInputsStore) Get() int {
	ctx := context.Background()
	num, err := b.rdb.Get(ctx, boardingInputsKey).Int()
	if err != nil {
		return 0
	}
	return num
}
