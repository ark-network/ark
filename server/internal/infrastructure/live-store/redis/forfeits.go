package redislivestore

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/redis/go-redis/v9"
)

type forfeitTxsStore struct {
	rdb     *redis.Client
	builder ports.TxBuilder
}

const (
	forfeitTxsStoreTxsKey     = "forfeitTxsStore:txs"
	forfeitTxsStoreConnsKey   = "forfeitTxsStore:connectors"
	forfeitTxsStoreVtxosKey   = "forfeitTxsStore:vtxos"
	forfeitTxsStoreConnIdxKey = "forfeitTxsStore:connidx"
)

func NewForfeitTxsStore(rdb *redis.Client, builder ports.TxBuilder) ports.ForfeitTxsStore {
	return &forfeitTxsStore{
		rdb:     rdb,
		builder: builder,
	}
}

func (s *forfeitTxsStore) Init(connectors []tree.TxGraphChunk, requests []domain.TxRequest) error {
	ctx := context.Background()
	vtxosToSign := make([]domain.Vtxo, 0)
	for _, request := range requests {
		for _, vtxo := range request.Inputs {
			if !vtxo.RequiresForfeit() {
				continue
			}
			vtxosToSign = append(vtxosToSign, vtxo)
		}
	}

	forfeitTxs := make(map[string]string)
	for _, vtxo := range vtxosToSign {
		forfeitTxs[vtxo.String()] = ""
	}

	connIndex := make(map[string]domain.Outpoint)
	if len(vtxosToSign) > 0 {
		connectorsOutpoints := make([]domain.Outpoint, 0)
		leaves := tree.TxGraphChunkList(connectors).Leaves()
		if len(leaves) == 0 {
			return fmt.Errorf("no connectors found")
		}
		for _, leaf := range leaves {
			connectorsOutpoints = append(connectorsOutpoints, domain.Outpoint{Txid: leaf.Txid, VOut: 0})
		}
		sort.Slice(vtxosToSign, func(i, j int) bool { return vtxosToSign[i].String() < vtxosToSign[j].String() })
		if len(vtxosToSign) > len(connectorsOutpoints) {
			return fmt.Errorf("more vtxos to sign than outpoints, %d > %d", len(vtxosToSign), len(connectorsOutpoints))
		}
		for i, vtxo := range vtxosToSign {
			connIndex[vtxo.String()] = connectorsOutpoints[i]
		}
	}
	// Store in Redis atomically
	pipe := s.rdb.TxPipeline()
	for vtxoKey, forfeit := range forfeitTxs {
		pipe.HSet(ctx, forfeitTxsStoreTxsKey, vtxoKey, forfeit)
	}
	connBytes, _ := json.Marshal(connectors)
	pipe.Set(ctx, forfeitTxsStoreConnsKey, connBytes, 0)
	vtxosBytes, _ := json.Marshal(vtxosToSign)
	pipe.Set(ctx, forfeitTxsStoreVtxosKey, vtxosBytes, 0)
	idxBytes, _ := json.Marshal(connIndex)
	pipe.Set(ctx, forfeitTxsStoreConnIdxKey, idxBytes, 0)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *forfeitTxsStore) Sign(txs []string) error {
	if len(txs) == 0 {
		return nil
	}
	ctx := context.Background()
	vtxosBytes, err := s.rdb.Get(ctx, forfeitTxsStoreVtxosKey).Bytes()
	if err != nil {
		return err
	}
	var vtxos []domain.Vtxo
	if err := json.Unmarshal(vtxosBytes, &vtxos); err != nil {
		return err
	}
	connBytes, err := s.rdb.Get(ctx, forfeitTxsStoreConnsKey).Bytes()
	if err != nil {
		return err
	}
	var connectors []tree.TxGraphChunk
	if err := json.Unmarshal(connBytes, &connectors); err != nil {
		return err
	}
	idxBytes, err := s.rdb.Get(ctx, forfeitTxsStoreConnIdxKey).Bytes()
	if err != nil {
		return err
	}
	connIndex := make(map[string]domain.Outpoint)
	if err := json.Unmarshal(idxBytes, &connIndex); err != nil {
		return err
	}
	if s.builder == nil {
		return fmt.Errorf("forfeitTxsStore builder not set")
	}
	validTxs, err := s.builder.VerifyForfeitTxs(vtxos, connectors, txs, connIndex)
	if err != nil {
		return err
	}

	pipe := s.rdb.TxPipeline()
	for vtxoKey, tx := range validTxs {
		pipe.HSet(ctx, forfeitTxsStoreTxsKey, vtxoKey.String(), tx)
	}
	_, err = pipe.Exec(ctx)

	return err
}

func (s *forfeitTxsStore) Reset() {
	ctx := context.Background()
	pipe := s.rdb.TxPipeline()
	pipe.Del(ctx, forfeitTxsStoreTxsKey)
	pipe.Del(ctx, forfeitTxsStoreConnsKey)
	pipe.Del(ctx, forfeitTxsStoreVtxosKey)
	pipe.Del(ctx, forfeitTxsStoreConnIdxKey)
	_, _ = pipe.Exec(ctx)
}

func (s *forfeitTxsStore) Pop() ([]string, error) {
	ctx := context.Background()
	hash, err := s.rdb.HGetAll(ctx, forfeitTxsStoreTxsKey).Result()
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(hash))
	for vtxo, forfeit := range hash {
		if len(forfeit) == 0 {
			return nil, fmt.Errorf("missing forfeit tx for vtxo %s", vtxo)
		}
		result = append(result, forfeit)
	}
	s.Reset()
	return result, nil
}

func (s *forfeitTxsStore) AllSigned() bool {
	ctx := context.Background()
	hash, err := s.rdb.HGetAll(ctx, forfeitTxsStoreTxsKey).Result()
	if err != nil {
		return false
	}
	for _, tx := range hash {
		if len(tx) == 0 {
			return false
		}
	}
	return true
}

func (s *forfeitTxsStore) Len() int {
	ctx := context.Background()
	count, err := s.rdb.HLen(ctx, forfeitTxsStoreTxsKey).Result()
	if err != nil {
		return 0
	}
	return int(count)
}

func (s *forfeitTxsStore) GetConnectorsIndexes() map[string]domain.Outpoint {
	ctx := context.Background()
	idxBytes, err := s.rdb.Get(ctx, forfeitTxsStoreConnIdxKey).Bytes()
	if err != nil {
		return nil
	}
	connIndex := make(map[string]domain.Outpoint)
	if err := json.Unmarshal(idxBytes, &connIndex); err != nil {
		return nil
	}
	return connIndex
}
