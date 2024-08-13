package application

import (
	"context"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	paymentsThreshold = int64(128)
	dustAmount        = uint64(450)
)

type Service interface {
	Start() error
	Stop()
	SpendVtxos(ctx context.Context, inputs []domain.VtxoKey) (string, error)
	ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver) error
	SignVtxos(ctx context.Context, forfeitTxs []string) error
	GetRoundByTxid(ctx context.Context, poolTxid string) (*domain.Round, error)
	GetRoundById(ctx context.Context, id string) (*domain.Round, error)
	GetCurrentRound(ctx context.Context) (*domain.Round, error)
	GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent
	UpdatePaymentStatus(
		ctx context.Context, paymentId string,
	) (unsignedForfeitTxs []string, currentRound *domain.Round, err error)
	ListVtxos(
		ctx context.Context, pubkey *secp256k1.PublicKey,
	) (spendableVtxos, spentVtxos []domain.Vtxo, err error)
	GetInfo(ctx context.Context) (*ServiceInfo, error)
	Onboard(
		ctx context.Context, boardingTx string,
		congestionTree tree.CongestionTree, userPubkey *secp256k1.PublicKey,
	) error
	// Async payments
	CreateAsyncPayment(
		ctx context.Context, inputs []domain.VtxoKey, receivers []domain.Receiver,
	) (string, []string, error)
	CompleteAsyncPayment(
		ctx context.Context, redeemTx string, unconditionalForfeitTxs []string,
	) error
}

type ServiceInfo struct {
	PubKey              string
	RoundLifetime       int64
	UnilateralExitDelay int64
	RoundInterval       int64
	Network             string
	MinRelayFee         int64
}

type WalletStatus struct {
	IsInitialized bool
	IsUnlocked    bool
	IsSynced      bool
}

type onboarding struct {
	tx             string
	congestionTree tree.CongestionTree
	userPubkey     *secp256k1.PublicKey
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
