package application

import (
	"context"
	"time"

	"github.com/ark-network/ark/common/bip322"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Service interface {
	Start() error
	Stop()
	RegisterIntent(ctx context.Context, bip322signature bip322.Signature, message tree.IntentMessage) (string, error)
	SpendVtxos(ctx context.Context, inputs []ports.Input) (string, error)
	ConfirmRegistration(ctx context.Context, intentId string) error
	ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver, cosignersPublicKeys []string) error
	SignVtxos(ctx context.Context, forfeitTxs []string) error
	SignRoundTx(ctx context.Context, roundTx string) error
	GetRoundByTxid(ctx context.Context, roundTxid string) (*domain.Round, error)
	GetRoundById(ctx context.Context, id string) (*domain.Round, error)
	GetCurrentRound(ctx context.Context) (*domain.Round, error)
	GetEventsChannel(ctx context.Context) <-chan []domain.Event
	ListVtxos(
		ctx context.Context, address string,
	) (spendableVtxos, spentVtxos []domain.Vtxo, err error)
	GetInfo(ctx context.Context) (*ServiceInfo, error)
	SubmitOffchainTx(ctx context.Context, checkpointTxs []string, signedRedeemTx string) (
		signedCheckpoints []string,
		finalRedeemTx string, redeemTxid string,
		err error,
	)
	FinalizeOffchainTx(
		ctx context.Context, txid string, finalCheckpoints []string,
	) error
	GetBoardingAddress(
		ctx context.Context, userPubkey *secp256k1.PublicKey,
	) (address string, scripts []string, err error)
	// Tree signing methods
	RegisterCosignerNonces(ctx context.Context, roundId, pubkey string, nonces tree.TreeNonces) error
	RegisterCosignerSignatures(ctx context.Context, roundId, pubkey string, signatures tree.TreePartialSigs) error
	GetTransactionEventsChannel(ctx context.Context) <-chan TransactionEvent
	GetMarketHourConfig(ctx context.Context) (*domain.MarketHour, error)
	UpdateMarketHourConfig(ctx context.Context, marketHourStartTime, marketHourEndTime time.Time, period, roundInterval time.Duration) error
	GetTxRequestQueue(ctx context.Context, requestIds ...string) ([]TxRequestInfo, error)
	DeleteTxRequests(ctx context.Context, requestIds ...string) error
	DeleteTxRequestsByProof(ctx context.Context, bip322signature bip322.Signature, message tree.DeleteIntentMessage) error

	// TODO remove this in v7
	GetIndexerTxChannel(ctx context.Context) <-chan TransactionEvent
}

type ServiceInfo struct {
	PubKey              string
	VtxoTreeExpiry      int64
	UnilateralExitDelay int64
	BoardingExitDelay   int64
	RoundInterval       int64
	Network             string
	Dust                uint64
	ForfeitAddress      string
	NextMarketHour      *NextMarketHour
	UtxoMinAmount       int64
	UtxoMaxAmount       int64
	VtxoMinAmount       int64
	VtxoMaxAmount       int64
}

type NextMarketHour struct {
	StartTime     time.Time
	EndTime       time.Time
	Period        time.Duration
	RoundInterval time.Duration
}

type WalletStatus struct {
	IsInitialized bool
	IsUnlocked    bool
	IsSynced      bool
}

type txOutpoint struct {
	txid string
	vout uint32
}

func (outpoint txOutpoint) GetTxid() string {
	return outpoint.txid
}

func (outpoint txOutpoint) GetIndex() uint32 {
	return outpoint.vout
}

const (
	RoundTransaction  TransactionEventType = "round_tx"
	RedeemTransaction TransactionEventType = "redeem_tx"
)

type TransactionEventType string

type TransactionEvent interface {
	Type() TransactionEventType
	GetSpentVtxos() []domain.Vtxo
	GetSpendableVtxos() []domain.Vtxo
	GetTxId() string
}

type RoundTransactionEvent struct {
	RoundTxid      string
	SpentVtxos     []domain.Vtxo
	SpendableVtxos []domain.Vtxo
	TxHex          string
}

func (r RoundTransactionEvent) Type() TransactionEventType {
	return RoundTransaction
}

func (r RoundTransactionEvent) GetTxId() string {
	return r.RoundTxid
}

func (r RoundTransactionEvent) GetSpentVtxos() []domain.Vtxo {
	return r.SpentVtxos
}

func (r RoundTransactionEvent) GetSpendableVtxos() []domain.Vtxo {
	return r.SpendableVtxos
}

type RedeemTransactionEvent struct {
	RedeemTxid     string
	SpentVtxos     []domain.Vtxo
	SpendableVtxos []domain.Vtxo
	TxHex          string
}

func (a RedeemTransactionEvent) Type() TransactionEventType {
	return RedeemTransaction
}

func (r RedeemTransactionEvent) GetTxId() string {
	return r.RedeemTxid
}

func (r RedeemTransactionEvent) GetSpentVtxos() []domain.Vtxo {
	return r.SpentVtxos
}

func (r RedeemTransactionEvent) GetSpendableVtxos() []domain.Vtxo {
	return r.SpendableVtxos
}

type TxRequestInfo struct {
	Id        string
	CreatedAt time.Time
	Receivers []struct {
		Address string
		Amount  uint64
	}
	Inputs         []domain.Vtxo
	BoardingInputs []ports.BoardingInput
	Cosigners      []string
}

type VtxoChainResp struct {
	Chain              []ChainWithExpiry
	Page               PageResp
	Depth              int32
	RootCommitmentTxid string
}

type VOut int

type CommitmentTxResp struct {
	StartedAt         int64
	EndAt             int64
	Batches           map[VOut]Batch
	TotalInputAmount  uint64
	TotalInputtVtxos  int32
	TotalOutputAmount uint64
	TotalOutputVtxos  int32
}

type CommitmentTxLeavesResp struct {
	Leaves []domain.Vtxo
	Page   PageResp
}

type Batch struct {
	TotalOutputAmount uint64
	TotalOutputVtxos  int32
	ExpiresAt         int64
	Swept             bool
}

type VtxoTreeResp struct {
	Nodes []Node
	Page  PageResp
}

type VtxoTreeLeavesResp struct {
	Leaves []domain.Vtxo
	Page   PageResp
}

type Node struct {
	Txid       string
	Tx         string
	ParentTxid string
	Level      int32
	LevelIndex int32
}

type ForfeitTxsResp struct {
	Txs  []string
	Page PageResp
}

type ConnectorResp struct {
	Connectors []Node
	Page       PageResp
}

type GetVtxosResp struct {
	Vtxos []domain.Vtxo
	Page  PageResp
}

type VirtualTxsResp struct {
	Transactions []string
	Page         PageResp
}

type SweptCommitmentTxResp struct {
	SweptBy []string
}

type Outpoint struct {
	Txid string
	Vout uint32
}

type TxType int

const (
	TxUnspecified TxType = iota
	TxReceived
	TxSent
)

type TxHistoryResp struct {
	Records []TxHistoryRecord
	Page    PageResp
}

type TxHistoryRecord struct {
	CommitmentTxid string
	VirtualTxid    string
	Type           TxType
	Amount         uint64
	CreatedAt      time.Time
	Settled        bool
	SettledBy      string
}

type Page struct {
	PageSize int32
	PageNum  int32
}

type PageResp struct {
	Current int32
	Next    int32
	Total   int32
}

type ChainTx struct {
	Txid string
	Type string
}

type ChainWithExpiry struct {
	Txid      string
	Txs       []ChainTx
	ExpiresAt int64
}
