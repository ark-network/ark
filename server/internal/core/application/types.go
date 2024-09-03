package application

import (
	"context"
	"fmt"

	"github.com/ark-network/ark/common/descriptor"
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
	SpendVtxos(ctx context.Context, inputs []Input) (string, error)
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
		ctx context.Context, inputs []domain.VtxoKey, receivers []domain.Receiver,
	) (string, []string, error)
	CompleteAsyncPayment(
		ctx context.Context, redeemTx string, unconditionalForfeitTxs []string,
	) error
	GetBoardingAddress(ctx context.Context, userPubkey *secp256k1.PublicKey) (string, error)
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
}

type ServiceInfo struct {
	PubKey                     string
	RoundLifetime              int64
	UnilateralExitDelay        int64
	RoundInterval              int64
	Network                    string
	MinRelayFee                int64
	BoardingDescriptorTemplate string
}

type WalletStatus struct {
	IsInitialized bool
	IsUnlocked    bool
	IsSynced      bool
}

type Input struct {
	Txid       string
	Index      uint32
	Descriptor string
}

func (i Input) IsVtxo() bool {
	return len(i.Descriptor) <= 0
}

func (i Input) VtxoKey() domain.VtxoKey {
	return domain.VtxoKey{
		Txid: i.Txid,
		VOut: i.Index,
	}
}

func (i Input) GetDescriptor() (*descriptor.TaprootDescriptor, error) {
	if i.IsVtxo() {
		return nil, fmt.Errorf("input is not a boarding input")
	}
	return descriptor.ParseTaprootDescriptor(i.Descriptor)
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
