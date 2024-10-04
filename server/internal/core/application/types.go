package application

import (
	"context"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	paymentsThreshold = int64(128)
)

type Service interface {
	Start() error
	Stop()
	SpendVtxos(ctx context.Context, inputs []ports.Input) (string, error)
	ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver) error
	SignVtxos(ctx context.Context, forfeitTxs []string) error
	SignRoundTx(ctx context.Context, roundTx string) error
	GetRoundByTxid(ctx context.Context, poolTxid string) (*domain.Round, error)
	GetRoundById(ctx context.Context, id string) (*domain.Round, error)
	GetCurrentRound(ctx context.Context) (*domain.Round, error)
	GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent
	UpdatePaymentStatus(
		ctx context.Context, paymentId string,
	) (lastEvent domain.RoundEvent, err error)
	ListVtxos(
		ctx context.Context, pubkey *secp256k1.PublicKey,
	) (spendableVtxos, spentVtxos []domain.Vtxo, err error)
	GetInfo(ctx context.Context) (*ServiceInfo, error)
	// Async payments
	CreateAsyncPayment(
		ctx context.Context, inputs []ports.Input, receivers []domain.Receiver,
	) (string, error)
	CompleteAsyncPayment(
		ctx context.Context, redeemTx string,
	) error
	GetBoardingAddress(
		ctx context.Context, userPubkey *secp256k1.PublicKey,
	) (address string, descriptor string, err error)
	// Tree signing methods
	RegisterCosignerPubkey(ctx context.Context, paymentId string, ephemeralPublicKey string) error
	RegisterCosignerNonces(
		ctx context.Context, roundID string,
		pubkey *secp256k1.PublicKey, nonces string,
	) error
	RegisterCosignerSignatures(
		ctx context.Context, roundID string,
		pubkey *secp256k1.PublicKey, signatures string,
	) error
	GetTransactionEventsChannel(ctx context.Context) <-chan TransactionEvent
}

type ServiceInfo struct {
	PubKey                     string
	RoundLifetime              int64
	UnilateralExitDelay        int64
	RoundInterval              int64
	Network                    string
	Dust                       uint64
	BoardingDescriptorTemplate string
	ForfeitAddress             string
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
}

type RoundTransactionEvent struct {
	RoundTxID             string
	SpentVtxos            []domain.VtxoKey
	SpendableVtxos        []domain.Vtxo
	ClaimedBoardingInputs []domain.VtxoKey
}

func (r RoundTransactionEvent) Type() TransactionEventType {
	return RoundTransaction
}

type RedeemTransactionEvent struct {
	AsyncTxID      string
	SpentVtxos     []domain.VtxoKey
	SpendableVtxos []domain.Vtxo
}

func (a RedeemTransactionEvent) Type() TransactionEventType {
	return RedeemTransaction
}
