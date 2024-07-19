package client

import (
	"context"
	"time"

	"github.com/ark-network/ark-sdk/explorer"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
)

const (
	GrpcClient = "grpc"
	RestClient = "rest"
)

type RoundEventChannel struct {
	Event *arkv1.GetEventStreamResponse
	Err   error
}

type Vtxo struct {
	Amount    uint64
	Txid      string
	VOut      uint32
	RoundTxid string
	ExpiresAt *time.Time
}

type Client interface {
	GetInfo(ctx context.Context) (*arkv1.GetInfoResponse, error)
	ListVtxos(ctx context.Context, addr string) (*arkv1.ListVtxosResponse, error)
	GetSpendableVtxos(
		ctx context.Context, addr string, explorerSvc explorer.Explorer,
	) ([]*Vtxo, error)
	GetRound(ctx context.Context, txID string) (*arkv1.GetRoundResponse, error)
	GetRoundByID(ctx context.Context, roundID string) (*arkv1.GetRoundByIdResponse, error)
	GetRedeemBranches(
		ctx context.Context, vtxos []*Vtxo, explorerSvc explorer.Explorer,
	) (map[string]*RedeemBranch, error)
	GetOffchainBalance(
		ctx context.Context, addr string, explorerSvc explorer.Explorer,
	) (uint64, map[int64]uint64, error)
	Onboard(
		ctx context.Context, req *arkv1.OnboardRequest,
	) (*arkv1.OnboardResponse, error)
	RegisterPayment(
		ctx context.Context, req *arkv1.RegisterPaymentRequest,
	) (*arkv1.RegisterPaymentResponse, error)
	ClaimPayment(
		ctx context.Context, req *arkv1.ClaimPaymentRequest,
	) (*arkv1.ClaimPaymentResponse, error)
	GetEventStream(
		ctx context.Context, paymentID string, req *arkv1.GetEventStreamRequest,
	) (<-chan RoundEventChannel, error)
	Ping(ctx context.Context, req *arkv1.PingRequest) (*arkv1.PingResponse, error)
	FinalizePayment(
		ctx context.Context, req *arkv1.FinalizePaymentRequest,
	) (*arkv1.FinalizePaymentResponse, error)
	Close()
}

type ClientFactory func(args ...interface{}) (Client, error)
