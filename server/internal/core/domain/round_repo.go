package domain

import (
	"context"

	"github.com/ark-network/ark/common/tree"
)

type RoundRepository interface {
	AddOrUpdateRound(ctx context.Context, round Round) error
	GetRoundWithId(ctx context.Context, id string) (*Round, error)
	GetRoundWithTxid(ctx context.Context, txid string) (*Round, error)
	GetRoundStats(ctx context.Context, roundTxid string) (*RoundStats, error)
	GetRoundForfeitTxs(ctx context.Context, roundTxid string) ([]ForfeitTx, error)
	GetRoundConnectorTree(ctx context.Context, roundTxid string) ([]tree.TxGraphChunk, error)
	GetVtxoTreeWithTxid(ctx context.Context, txid string) ([]tree.TxGraphChunk, error)
	GetUnsweptRoundsTxid(ctx context.Context) ([]string, error)
	GetRoundsIds(ctx context.Context, startedAfter int64, startedBefore int64) ([]string, error)
	GetSweptRoundsConnectorAddress(ctx context.Context) ([]string, error)
	GetTxsWithTxids(ctx context.Context, txids []string) ([]string, error)
	GetExistingRounds(ctx context.Context, txids []string) (map[string]any, error)
	Close()
}

type RoundStats struct {
	Swept              bool
	TotalForfeitAmount uint64
	TotalInputVtxos    int32
	TotalBatchAmount   uint64
	TotalOutputVtxos   int32
	ExpiresAt          int64
	Started            int64
	Ended              int64
}
