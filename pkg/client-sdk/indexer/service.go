package indexer

import "context"

type Indexer interface {
	GetCommitmentTx(ctx context.Context, txid string) (*CommitmentTx, error)
	GetCommitmentTxLeaves(ctx context.Context, txid string, opts ...RequestOption) (*CommitmentTxLeavesResponse, error)
	GetVtxoTree(ctx context.Context, batchOutpoint Outpoint, opts ...RequestOption) (*VtxoTreeResponse, error)
	GetVtxoTreeLeaves(ctx context.Context, batchOutpoint Outpoint, opts ...RequestOption) (*VtxoTreeLeavesResponse, error)
	GetForfeitTxs(ctx context.Context, txid string, opts ...RequestOption) (*ForfeitTxsResponse, error)
	GetConnectors(ctx context.Context, txid string, opts ...RequestOption) (*ConnectorsResponse, error)
	GetVtxos(ctx context.Context, opts ...GetVtxosRequestOption) (*VtxosResponse, error)
	GetTransactionHistory(ctx context.Context, address string, opts ...GetTxHistoryRequestOption) (*TxHistoryResponse, error)
	GetVtxoChain(ctx context.Context, outpoint Outpoint, opts ...RequestOption) (*VtxoChainResponse, error)
	GetVirtualTxs(ctx context.Context, txids []string, opts ...RequestOption) (*VirtualTxsResponse, error)
	GetSweptCommitmentTx(ctx context.Context, txid string) ([]string, error)
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
	Vtxos []Vtxo
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

type PageRequest struct {
	Size  int32
	Index int32
}

type PageResponse struct {
	Current int32
	Next    int32
	Total   int32
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
type Vtxo struct {
	Outpoint       Outpoint
	CreatedAt      int64
	ExpiresAt      int64
	Amount         uint64
	Script         string
	IsLeaf         bool
	IsSwept        bool
	IsSpent        bool
	SpentBy        string
	CommitmentTxid string
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
	VirtualTxid    string
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
