package application

import (
	"context"
	"time"

	"github.com/ark-network/ark/common/note"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	txRequestsThreshold = int64(128)
)

type Service interface {
	Start() error
	Stop()
	SpendNotes(ctx context.Context, notes []note.Note) (string, error)
	SpendVtxos(ctx context.Context, inputs []ports.Input) (string, error)
	ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver, musig2Data *tree.Musig2) error
	SignVtxos(ctx context.Context, forfeitTxs []string) error
	SignRoundTx(ctx context.Context, roundTx string) error
	GetRoundByTxid(ctx context.Context, roundTxid string) (*domain.Round, error)
	GetRoundById(ctx context.Context, id string) (*domain.Round, error)
	GetCurrentRound(ctx context.Context) (*domain.Round, error)
	GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent
	UpdateTxRequestStatus(ctx context.Context, requestID string) error
	ListVtxos(
		ctx context.Context, address string,
	) (spendableVtxos, spentVtxos []domain.Vtxo, err error)
	GetInfo(ctx context.Context) (*ServiceInfo, error)
	SubmitRedeemTx(ctx context.Context, redeemTx string) (signedRedeemTx, redeemTxid string, err error)
	GetBoardingAddress(
		ctx context.Context, userPubkey *secp256k1.PublicKey,
	) (address string, scripts []string, err error)
	// Tree signing methods
	RegisterCosignerNonces(
		ctx context.Context, roundID string,
		pubkey *secp256k1.PublicKey, nonces string,
	) error
	RegisterCosignerSignatures(
		ctx context.Context, roundID string,
		pubkey *secp256k1.PublicKey, signatures string,
	) error
	GetTransactionEventsChannel(ctx context.Context) <-chan TransactionEvent
	SetNostrRecipient(ctx context.Context, nostrRecipient string, signedVtxoOutpoints []SignedVtxoOutpoint) error
	DeleteNostrRecipient(ctx context.Context, signedVtxoOutpoints []SignedVtxoOutpoint) error
	GetMarketHourConfig(ctx context.Context) (*domain.MarketHour, error)
	UpdateMarketHourConfig(ctx context.Context, marketHourStartTime, marketHourEndTime time.Time, period, roundInterval time.Duration) error
}

type ServiceInfo struct {
	PubKey              string
	VtxoTreeExpiry      int64
	UnilateralExitDelay int64
	RoundInterval       int64
	Network             string
	Dust                uint64
	ForfeitAddress      string
	NextMarketHour      *NextMarketHour
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

type SignedVtxoOutpoint struct {
	Outpoint domain.VtxoKey
	Proof    OwnershipProof
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
}

type RoundTransactionEvent struct {
	RoundTxid             string
	SpentVtxos            []domain.VtxoKey
	SpendableVtxos        []domain.Vtxo
	ClaimedBoardingInputs []domain.VtxoKey
}

func (r RoundTransactionEvent) Type() TransactionEventType {
	return RoundTransaction
}

type RedeemTransactionEvent struct {
	RedeemTxid     string
	SpentVtxos     []domain.VtxoKey
	SpendableVtxos []domain.Vtxo
}

func (a RedeemTransactionEvent) Type() TransactionEventType {
	return RedeemTransaction
}
