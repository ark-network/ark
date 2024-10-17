package client

import (
	"context"
	"time"

	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
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
	RegisterInputsForNextRound(
		ctx context.Context, inputs []Input, ephemeralKey string,
	) (string, error)
	RegisterOutputsForNextRound(
		ctx context.Context, paymentID string, outputs []Output,
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
		ctx context.Context, paymentID string,
	) (<-chan RoundEventChannel, func(), error)
	Ping(ctx context.Context, paymentID string) (RoundEvent, error)
	CreatePayment(
		ctx context.Context, inputs []AsyncPaymentInput, outputs []Output,
	) (string, error)
	CompletePayment(
		ctx context.Context, signedRedeemTx string,
	) error
	ListVtxos(ctx context.Context, addr string) ([]Vtxo, []Vtxo, error)
	GetRound(ctx context.Context, txID string) (*Round, error)
	GetRoundByID(ctx context.Context, roundID string) (*Round, error)
	Close()
}

type Info struct {
	Pubkey                     string
	RoundLifetime              int64
	UnilateralExitDelay        int64
	RoundInterval              int64
	Network                    string
	Dust                       uint64
	BoardingDescriptorTemplate string
	ForfeitAddress             string
}

type RoundEventChannel struct {
	Event RoundEvent
	Err   error
}

type Outpoint struct {
	Txid string
	VOut uint32
}

type Input struct {
	Outpoint
	Descriptor string
}

type AsyncPaymentInput struct {
	Input
	ForfeitLeafHash chainhash.Hash
}

type Vtxo struct {
	Outpoint
	Address   string
	Amount    uint64
	RoundTxid string
	ExpiresAt *time.Time
	RedeemTx  string
	Pending   bool
	SpentBy   string
}

type DescriptorVtxo struct {
	Vtxo
	Descriptor string
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
	Tree       tree.CongestionTree
	ForfeitTxs []string
	Connectors []string
	Stage      RoundStage
}

type RoundFinalizationEvent struct {
	ID              string
	Tx              string
	Tree            tree.CongestionTree
	Connectors      []string
	MinRelayFeeRate chainfee.SatPerKVByte
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
	UnsignedRoundTx     string
}

func (e RoundSigningStartedEvent) isRoundEvent() {}

type RoundSigningNoncesGeneratedEvent struct {
	ID     string
	Nonces bitcointree.TreeNonces
}

func (e RoundSigningNoncesGeneratedEvent) isRoundEvent() {}
