package domain

import (
	"context"

	"github.com/ark-network/ark/common/tree"
)

type RoundEventRepository interface {
	Save(ctx context.Context, id string, events ...RoundEvent) (*Round, error)
	Load(ctx context.Context, id string) (*Round, error)
	RegisterEventsHandler(func(*Round))
	Close()
}

type RoundRepository interface {
	AddOrUpdateRound(ctx context.Context, round Round) error
	GetRoundWithId(ctx context.Context, id string) (*Round, error)
	GetRoundWithTxid(ctx context.Context, txid string) (*Round, error)
	GetRoundStats(ctx context.Context, roundTxid string) (*RoundStats, error)
	GetRoundForfeitTxs(ctx context.Context, roundTxid string) ([]ForfeitTx, error)
	GetRoundConnectorTree(ctx context.Context, roundTxid string) (tree.TxTree, error)
	GetVtxoTreeWithTxid(ctx context.Context, txid string) (tree.TxTree, error)
	GetExpiredRoundsTxid(ctx context.Context) ([]string, error)
	GetRoundsIds(ctx context.Context, startedAfter int64, startedBefore int64) ([]string, error)
	GetSweptRoundsConnectorAddress(ctx context.Context) ([]string, error)
	GetTxsWithTxids(ctx context.Context, txids []string) ([]string, error)
	Close()
}

type VtxoRepository interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) error
	SpendVtxos(ctx context.Context, vtxos []VtxoKey, txid string) error
	RedeemVtxos(ctx context.Context, vtxos []VtxoKey) error
	GetVtxos(ctx context.Context, vtxos []VtxoKey) ([]Vtxo, error)
	GetVtxosForRound(ctx context.Context, txid string) ([]Vtxo, error)
	SweepVtxos(ctx context.Context, vtxos []VtxoKey) error
	GetAllNonRedeemedVtxos(ctx context.Context, pubkey string) ([]Vtxo, []Vtxo, error)
	GetAllSweepableVtxos(ctx context.Context) ([]Vtxo, error)
	GetSpendableVtxosWithPubKey(ctx context.Context, pubkey string) ([]Vtxo, error)
	GetAll(ctx context.Context) ([]Vtxo, error)
	GetAllVtxosWithPubKey(ctx context.Context, pubkey string) ([]Vtxo, []Vtxo, error)
	UpdateExpireAt(ctx context.Context, vtxos []VtxoKey, expireAt int64) error
	Close()
}

type MarketHourRepo interface {
	Get(ctx context.Context) (*MarketHour, error)
	Upsert(ctx context.Context, marketHour MarketHour) error
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
