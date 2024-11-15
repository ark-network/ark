package client

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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
	Ping(ctx context.Context, paymentID string) error
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
	GetTransactionsStream(ctx context.Context) (<-chan TransactionEvent, func(), error)
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

func (o Outpoint) Equals(other Outpoint) bool {
	return o.Txid == other.Txid && o.VOut == other.VOut
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
	Pubkey    string
	Amount    uint64
	RoundTxid string
	ExpiresAt time.Time
	CreatedAt time.Time
	RedeemTx  string
	IsOOR     bool
	SpentBy   string
}

func (v Vtxo) Address(asp *secp256k1.PublicKey, net common.Network) (string, error) {
	pubkeyBytes, err := hex.DecodeString(v.Pubkey)
	if err != nil {
		return "", err
	}

	pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return "", err
	}

	a := &common.Address{
		HRP:        net.Addr,
		Asp:        asp,
		VtxoTapKey: pubkey,
	}

	return a.Encode()
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

type TransactionEvent struct {
	Round  *RoundTransaction
	Redeem *RedeemTransaction
	Err    error
}

type RoundTransaction struct {
	Txid                 string
	SpentVtxos           []Outpoint
	SpendableVtxos       []Vtxo
	ClaimedBoardingUtxos []Outpoint
}

type RedeemTransaction struct {
	Txid           string
	SpentVtxos     []Outpoint
	SpendableVtxos []Vtxo
}
