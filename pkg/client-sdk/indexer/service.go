package indexer

import (
	"context"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/types"
)

type Indexer interface {
	GetCommitmentTx(ctx context.Context, txid string) (*CommitmentTx, error)
	GetCommitmentTxLeaves(ctx context.Context, txid string, opts ...RequestOption) (*CommitmentTxLeavesResponse, error)
	GetVtxoTree(ctx context.Context, batchOutpoint Outpoint, opts ...RequestOption) (*VtxoTreeResponse, error)
	GetFullVtxoTree(ctx context.Context, batchOutpoint Outpoint, opts ...RequestOption) (tree.TxTree, error)
	GetVtxoTreeLeaves(ctx context.Context, batchOutpoint Outpoint, opts ...RequestOption) (*VtxoTreeLeavesResponse, error)
	GetForfeitTxs(ctx context.Context, txid string, opts ...RequestOption) (*ForfeitTxsResponse, error)
	GetConnectors(ctx context.Context, txid string, opts ...RequestOption) (*ConnectorsResponse, error)
	GetVtxos(ctx context.Context, opts ...GetVtxosRequestOption) (*VtxosResponse, error)
	GetTransactionHistory(ctx context.Context, address string, opts ...GetTxHistoryRequestOption) (*TxHistoryResponse, error)
	GetVtxoChain(ctx context.Context, outpoint Outpoint, opts ...RequestOption) (*VtxoChainResponse, error)
	GetVirtualTxs(ctx context.Context, txids []string, opts ...RequestOption) (*VirtualTxsResponse, error)
	GetSweptCommitmentTx(ctx context.Context, txid string) ([]string, error)
	SubscribeForScripts(ctx context.Context, subscriptionId string, scripts []string) (string, error)
	UnsubscribeForScripts(ctx context.Context, subscriptionId string, scripts []string) error
	GetSubscription(ctx context.Context, subscriptionId string) (<-chan *ScriptEvent, func(), error)

	Close()
}

type CommitmentTxLeavesResponse struct {
	Leaves []Outpoint
	Page   *PageResponse
}

type VtxoTreeResponse struct {
	Tree []TxNode
	Page *PageResponse
}

type VtxoTreeLeavesResponse struct {
	Leaves []Outpoint
	Page   *PageResponse
}

type ForfeitTxsResponse struct {
	Txids []string
	Page  *PageResponse
}

type ConnectorsResponse struct {
	Tree []TxNode
	Page *PageResponse
}

type VtxosResponse struct {
	Vtxos []types.Vtxo
	Page  *PageResponse
}

type TxHistoryResponse struct {
	History []TxHistoryRecord
	Page    *PageResponse
}

type VtxoChainResponse struct {
	Chain              []ChainWithExpiry
	Depth              int32
	RootCommitmentTxid string
	Page               *PageResponse
}

type VirtualTxsResponse struct {
	Txs  []string
	Page *PageResponse
}

type ScriptEvent struct {
	Txid       string
	Scripts    []string
	NewVtxos   []types.Vtxo
	SpentVtxos []types.Vtxo
	Err        error
}

type PageRequest struct {
	Size  int32
	Index int32
}

type PageResponse struct {
	Current int32
	Next    int32
	Total   int32
}

type TxNodes []TxNode

func (t TxNodes) ToTree(txMap map[string]string) tree.TxTree {
	vtxoTree := make(tree.TxTree, 0)
	for _, node := range t {
		if len(vtxoTree) <= int(node.Level) {
			vtxoTree = extendArray(vtxoTree, int(node.Level))
		}
		if len(vtxoTree[node.Level]) <= int(node.LevelIndex) {
			vtxoTree[node.Level] = extendArray(vtxoTree[node.Level], int(node.LevelIndex))
		}
		vtxoTree[node.Level][node.LevelIndex] = tree.Node{
			Txid:       node.Txid,
			ParentTxid: node.ParentTxid,
			Level:      node.Level,
			LevelIndex: node.LevelIndex,
			Tx:         txMap[node.Txid],
		}
	}
	return vtxoTree
}

func (t TxNodes) Txids() []string {
	txids := make([]string, 0, len(t))
	for _, node := range t {
		txids = append(txids, node.Txid)
	}
	return txids
}

type TxNode struct {
	Txid       string
	ParentTxid string
	Level      int32
	LevelIndex int32
}

type Batch struct {
	TotalOutputAmount uint64
	TotalOutputVtxos  int32
	ExpiresAt         int64
	Swept             bool
}

type CommitmentTx struct {
	StartedAt         int64
	EndedAt           int64
	TotalInputAmount  uint64
	TotalInputVtxos   int32
	TotalOutputAmount uint64
	TotalOutputVtxos  int32
	Batches           map[uint32]*Batch
}

type Outpoint struct {
	Txid string
	VOut uint32
}

type TxType int

const (
	TxTypeUnspecified TxType = iota
	TxTypeReceived
	TxTypeSent
	TxTypeSweep
)

type TxHistoryRecord struct {
	CommitmentTxid string
	ArkTxid        string
	Type           TxType
	Amount         uint64
	CreatedAt      int64
	IsSettled      bool
	SettledBy      string
}

type ChainWithExpiry struct {
	Txid      string
	Spends    []ChainTx
	ExpiresAt int64
}

type ChainTx struct {
	Txid string
	Type string
}
