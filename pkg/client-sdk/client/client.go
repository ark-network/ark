package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

const (
	GrpcClient = "grpc"
	RestClient = "rest"
)

var (
	ErrConnectionClosedByServer = fmt.Errorf("connection closed by server")
)

type RoundEvent interface {
	isRoundEvent()
}

type TransportClient interface {
	GetInfo(ctx context.Context) (*Info, error)
	RegisterInputsForNextRound(
		ctx context.Context, inputs []Input,
	) (string, error)
	RegisterNotesForNextRound(
		ctx context.Context, notes []string,
	) (string, error)
	RegisterOutputsForNextRound(
		ctx context.Context, requestID string, outputs []Output, musig2 *tree.Musig2,
	) error
	SubmitTreeNonces(
		ctx context.Context, roundID, cosignerPubkey string, nonces bitcointree.TreeNonces,
	) error
	SubmitTreeSignatures(
		ctx context.Context, roundID, cosignerPubkey string, signatures bitcointree.TreePartialSigs,
	) error
	SubmitSignedForfeitTxs(
		ctx context.Context, signedForfeitTxs []string, signedRoundTx string,
	) error
	GetEventStream(
		ctx context.Context, requestID string,
	) (<-chan RoundEventChannel, func(), error)
	Ping(ctx context.Context, requestID string) error
	SubmitRedeemTx(
		ctx context.Context, partialSignedRedeemTx string,
	) (signedRedeemTx, redeemTxid string, err error)
	ListVtxos(ctx context.Context, addr string) ([]Vtxo, []Vtxo, error)
	GetRound(ctx context.Context, txID string) (*Round, error)
	GetRoundByID(ctx context.Context, roundID string) (*Round, error)
	Close()
	GetTransactionsStream(ctx context.Context) (<-chan TransactionEvent, func(), error)
	SetNostrRecipient(ctx context.Context, nostrRecipient string, vtxos []SignedVtxoOutpoint) error
	DeleteNostrRecipient(ctx context.Context, vtxos []SignedVtxoOutpoint) error
	SubscribeForAddress(ctx context.Context, address string) (<-chan AddressEvent, func(), error)

	// IndexerService methods
	GetCommitmentTx(ctx context.Context, txid string) (*CommitmentTxInfo, error)
	GetVtxoTree(ctx context.Context, batchOutpoint Outpoint, page PageRequest) (*VtxoTreeResponse, error)
	GetForfeitTxs(ctx context.Context, batchOutpoint Outpoint, page PageRequest) (*ForfeitTxsResponse, error)
	GetConnectors(ctx context.Context, batchOutpoint Outpoint, page PageRequest) (*ConnectorsResponse, error)
	GetSpendableVtxos(ctx context.Context, address string, page PageRequest) (*SpendableVtxosResponse, error)
	GetTransactionHistory(ctx context.Context, address string, startTime, endTime int64, page PageRequest) (*TransactionHistoryResponse, error)
	GetVtxoChain(ctx context.Context, outpoint Outpoint, page PageRequest) (*VtxoChainResponse, error)
	GetVirtualTxs(ctx context.Context, txids []string, page PageRequest) (*VirtualTxsResponse, error)
	GetSweptCommitmentTx(ctx context.Context, txid string) (*SweptCommitmentTxResponse, error)
}

type Info struct {
	Version                    string
	PubKey                     string
	VtxoTreeExpiry             int64
	UnilateralExitDelay        int64
	RoundInterval              int64
	Network                    string
	Dust                       uint64
	BoardingDescriptorTemplate string
	ForfeitAddress             string
	MarketHourStartTime        int64
	MarketHourEndTime          int64
	MarketHourPeriod           int64
	MarketHourRoundInterval    int64
	UtxoMinAmount              int64
	UtxoMaxAmount              int64
	VtxoMinAmount              int64
	VtxoMaxAmount              int64
}

type RoundEventChannel struct {
	Event RoundEvent
	Err   error
}

type Outpoint struct {
	Txid string
	VOut uint32
}

func (o Outpoint) String() string {
	return fmt.Sprintf("%s:%d", o.Txid, o.VOut)
}

func (o Outpoint) Equals(other Outpoint) bool {
	return o.Txid == other.Txid && o.VOut == other.VOut
}

type Input struct {
	Outpoint
	Tapscripts []string
}

type Vtxo struct {
	Outpoint
	PubKey    string
	Amount    uint64
	RoundTxid string
	ExpiresAt time.Time
	CreatedAt time.Time
	RedeemTx  string
	IsPending bool
	SpentBy   string
}

func (v Vtxo) Address(server *secp256k1.PublicKey, net common.Network) (string, error) {
	pubkeyBytes, err := hex.DecodeString(v.PubKey)
	if err != nil {
		return "", err
	}

	pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return "", err
	}

	a := &common.Address{
		HRP:        net.Addr,
		Server:     server,
		VtxoTapKey: pubkey,
	}

	return a.Encode()
}

type TapscriptsVtxo struct {
	Vtxo
	Tapscripts []string
}

type Output struct {
	Address string // onchain or offchain address
	Amount  uint64
}

type RoundStage int

func (s RoundStage) String() string {
	switch s {
	case RoundStageRegistration:
		return "ROUND_STAGE_REGISTRATION"
	case RoundStageFinalization:
		return "ROUND_STAGE_FINALIZATION"
	case RoundStageFinalized:
		return "ROUND_STAGE_FINALIZED"
	case RoundStageFailed:
		return "ROUND_STAGE_FAILED"
	default:
		return "ROUND_STAGE_UNDEFINED"
	}
}

const (
	RoundStageUndefined RoundStage = iota
	RoundStageRegistration
	RoundStageFinalization
	RoundStageFinalized
	RoundStageFailed
)

type Round struct {
	ID         string
	StartedAt  *time.Time
	EndedAt    *time.Time
	Tx         string
	Tree       tree.TxTree
	ForfeitTxs []string
	Connectors tree.TxTree
	Stage      RoundStage
}

type RoundFinalizationEvent struct {
	ID              string
	Tx              string
	Tree            tree.TxTree
	Connectors      tree.TxTree
	MinRelayFeeRate chainfee.SatPerKVByte
	ConnectorsIndex map[string]Outpoint // <txid:vout> -> outpoint
}

func (e RoundFinalizationEvent) isRoundEvent() {}

type RoundFinalizedEvent struct {
	ID   string
	Txid string
}

func (e RoundFinalizedEvent) isRoundEvent() {}

type RoundFailedEvent struct {
	ID     string
	Reason string
}

func (e RoundFailedEvent) isRoundEvent() {}

type RoundSigningStartedEvent struct {
	ID               string
	UnsignedTree     tree.TxTree
	UnsignedRoundTx  string
	CosignersPubkeys []string
}

func (e RoundSigningStartedEvent) isRoundEvent() {}

type RoundSigningNoncesGeneratedEvent struct {
	ID     string
	Nonces bitcointree.TreeNonces
}

func (e RoundSigningNoncesGeneratedEvent) isRoundEvent() {}

type TransactionEvent struct {
	Round  *RoundTransaction
	Redeem *RedeemTransaction
	Err    error
}

type RoundTransaction struct {
	Txid                 string
	SpentVtxos           []Vtxo
	SpendableVtxos       []Vtxo
	ClaimedBoardingUtxos []Outpoint
	Hex                  string
}

type RedeemTransaction struct {
	Txid           string
	SpentVtxos     []Vtxo
	SpendableVtxos []Vtxo
	Hex            string
}

type SignedVtxoOutpoint struct {
	Outpoint
	Proof OwnershipProof
}

type OwnershipProof struct {
	ControlBlock string
	Script       string
	Signature    string
}

type AddressEvent struct {
	NewVtxos   []Vtxo
	SpentVtxos []Vtxo
	Err        error
}

// IndexerService types

type PageRequest struct {
	Size  int32
	Index int32
}

type PageResponse struct {
	Current int32
	Next    int32
	Total   int32
}

type IndexerNode struct {
	Txid       string
	ParentTxid string
	Level      int32
	LevelIndex int32
}

type Batch struct {
	TotalBatchAmount   uint64
	TotalForfeitAmount uint64
	TotalInputVtxos    int32
	TotalOutputVtxos   int32
	ExpiresAt          int64
	Swept              bool
}

type CommitmentTxInfo struct {
	StartedAt int64
	EndedAt   int64
	Batches   map[uint32]*Batch
}

type VtxoTreeResponse struct {
	VtxoTree []IndexerNode
	Page     PageResponse
}

type ForfeitTxsResponse struct {
	Txs  []string
	Page PageResponse
}

type ConnectorsResponse struct {
	Connectors []IndexerNode
	Page       PageResponse
}

type IndexerVtxo struct {
	Outpoint  Outpoint
	CreatedAt int64
	ExpiresAt int64
	Amount    uint64
	Script    string
	IsLeaf    bool
	IsSwept   bool
	IsSpent   bool
	SpentBy   string
}

type SpendableVtxosResponse struct {
	Vtxos []IndexerVtxo
	Page  PageResponse
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
	ConfirmedAt    int64
	IsSettled      bool
}

type TransactionHistoryResponse struct {
	History []TxHistoryRecord
	Page    PageResponse
}

type ChainWithExpiry struct {
	Txs       []ChainTx
	ExpiresAt int64
}

type ChainTx struct {
	Txid string
	Type string
}

type VtxoChainResponse struct {
	Graph map[string]*ChainWithExpiry
	Page  PageResponse
}

type VirtualTxsResponse struct {
	Txs  []string
	Page PageResponse
}

type SweptCommitmentTxResponse struct {
	SweptBy []string
}

type AddressesSubscriptionEvent struct {
	Address    string
	NewVtxos   []IndexerVtxo
	SpentVtxos []IndexerVtxo
	Err        error
}
