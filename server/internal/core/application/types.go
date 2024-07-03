package application

import (
	"context"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
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
	GetCurrentRound(ctx context.Context) (*domain.Round, error)
	GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent
	UpdatePaymentStatus(ctx context.Context, id string) (unsignedForfeitTxs []string, err error)
	ListVtxos(ctx context.Context, pubkey *secp256k1.PublicKey) ([]domain.Vtxo, []domain.Vtxo, error)
	GetInfo(ctx context.Context) (*ServiceInfo, error)
	Onboard(ctx context.Context, boardingTx string, congestionTree tree.CongestionTree, userPubkey *secp256k1.PublicKey) error
	TrustedOnboarding(ctx context.Context, userPubKey *secp256k1.PublicKey) (string, error)
}

type ServiceInfo struct {
	PubKey              string
	RoundLifetime       int64
	UnilateralExitDelay int64
	RoundInterval       int64
	Network             string
	MinRelayFee         int64
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
