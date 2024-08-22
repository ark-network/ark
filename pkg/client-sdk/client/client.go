package client

import (
	"context"
	"time"

	"github.com/ark-network/ark/common/tree"
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
	Onboard(
		ctx context.Context, tx, userPubkey string, congestionTree tree.CongestionTree,
	) error
	RegisterPayment(
		ctx context.Context, inputs []VtxoKey,
	) (string, error)
	ClaimPayment(
		ctx context.Context, paymentID string, outputs []Output,
	) error
	GetEventStream(
		ctx context.Context, paymentID string,
	) (<-chan RoundEventChannel, error)
	Ping(ctx context.Context, paymentID string) (*RoundFinalizationEvent, error)
	FinalizePayment(
		ctx context.Context, signedForfeitTxs []string,
	) error
	CreatePayment(
		ctx context.Context, inputs []VtxoKey, outputs []Output,
	) (string, []string, error)
	CompletePayment(
		ctx context.Context, signedRedeemTx string, signedUnconditionalForfeitTxs []string,
	) error
	Close()
}

type Info struct {
	Pubkey              string
	RoundLifetime       int64
	UnilateralExitDelay int64
	RoundInterval       int64
	Network             string
	MinRelayFee         int64
}

type RoundEventChannel struct {
	Event RoundEvent
	Err   error
}

type VtxoKey struct {
	Txid string
	VOut uint32
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
	Payments   []Payment
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

type Payment struct {
	TxID    string
	VOut    uint32
	Spent   bool
	Pending bool
	Amount  uint64
	PubKey  string
}
