package client

import (
	"context"
	"time"

	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	GrpcClient = "grpc"
	RestClient = "rest"
)

type RoundEvent interface {
	isRoundEvent()
}

type ASPClient interface {
	GetInfo(ctx context.Context) (*Info, error)
	ListVtxos(ctx context.Context, addr string) ([]Vtxo, []Vtxo, error)
	GetRound(ctx context.Context, txID string) (*Round, error)
	GetRoundByID(ctx context.Context, roundID string) (*Round, error)
	RegisterPayment(
		ctx context.Context, inputs []Input, ephemeralKey string,
	) (string, error)
	ClaimPayment(
		ctx context.Context, paymentID string, outputs []Output,
	) error
	GetEventStream(
		ctx context.Context, paymentID string,
	) (<-chan RoundEventChannel, error)
	Ping(ctx context.Context, paymentID string) (RoundEvent, error)
	FinalizePayment(
		ctx context.Context, signedForfeitTxs []string, signedRoundTx string,
	) error
	CreatePayment(
		ctx context.Context, inputs []VtxoKey, outputs []Output,
	) (string, []string, error)
	CompletePayment(
		ctx context.Context, signedRedeemTx string, signedUnconditionalForfeitTxs []string,
	) error
	ReverseBoardingAddress(ctx context.Context, userPubkey string) (string, error)
	SendTreeNonces(
		ctx context.Context, roundID, cosignerPubkey string, nonces bitcointree.TreeNonces,
	) error
	SendTreeSignatures(
		ctx context.Context, roundID, cosignerPubkey string, signatures bitcointree.TreePartialSigs,
	) error
	Close()
}

type Info struct {
	Pubkey              string
	RoundLifetime       int64
	UnilateralExitDelay int64
	OnboardingExitDelay int64
	RoundInterval       int64
	Network             string
	MinRelayFee         int64
}

type RoundEventChannel struct {
	Event RoundEvent
	Err   error
}

type Input interface {
	ReverseBoardingPublicKey() string
	GetTxID() string
	GetVOut() uint32
}

type VtxoKey struct {
	Txid string
	VOut uint32
}

func (k VtxoKey) GetTxID() string {
	return k.Txid
}

func (k VtxoKey) GetVOut() uint32 {
	return k.VOut
}

func (k VtxoKey) ReverseBoardingPublicKey() string {
	return ""
}

type BoardingInput struct {
	VtxoKey
	UserPubkey string
}

func (k BoardingInput) ReverseBoardingPublicKey() string {
	return k.UserPubkey
}

type Vtxo struct {
	VtxoKey
	Amount                  uint64
	RoundTxid               string
	ExpiresAt               *time.Time
	RedeemTx                string
	UnconditionalForfeitTxs []string
	Pending                 bool
}

type Output struct {
	Address string
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
	Tree       tree.CongestionTree
	ForfeitTxs []string
	Connectors []string
	Stage      RoundStage
}

type RoundFinalizationEvent struct {
	ID         string
	Tx         string
	ForfeitTxs []string
	Tree       tree.CongestionTree
	Connectors []string
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
	ID                  string
	UnsignedTree        tree.CongestionTree
	CosignersPublicKeys []*secp256k1.PublicKey
}

func (e RoundSigningStartedEvent) isRoundEvent() {}

type RoundSigningNoncesGeneratedEvent struct {
	ID     string
	Nonces bitcointree.TreeNonces
}

func (e RoundSigningNoncesGeneratedEvent) isRoundEvent() {}
