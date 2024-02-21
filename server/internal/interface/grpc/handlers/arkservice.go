package handlers

import (
	"context"
	"encoding/hex"
	"sync"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/application"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type listener struct {
	id string
	ch chan *arkv1.GetEventStreamResponse
}

type handler struct {
	svc application.Service

	listenersLock *sync.Mutex
	listeners     []*listener
}

func NewHandler(service application.Service) arkv1.ArkServiceServer {
	h := &handler{
		svc:           service,
		listenersLock: &sync.Mutex{},
		listeners:     make([]*listener, 0),
	}

	go h.listenToEvents()

	return h
}

func (h *handler) Ping(ctx context.Context, req *arkv1.PingRequest) (*arkv1.PingResponse, error) {
	if req.GetPaymentId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing payment id")
	}

	if err := h.svc.UpdatePaymentStatus(ctx, req.GetPaymentId()); err != nil {
		return nil, err
	}

	return &arkv1.PingResponse{}, nil
}

func (h *handler) RegisterPayment(ctx context.Context, req *arkv1.RegisterPaymentRequest) (*arkv1.RegisterPaymentResponse, error) {
	vtxosKeys := make([]domain.VtxoKey, 0, len(req.GetInputs()))
	for _, input := range req.GetInputs() {
		vtxosKeys = append(vtxosKeys, domain.VtxoKey{
			Txid: input.GetTxid(),
			VOut: input.GetVout(),
		})
	}

	id, err := h.svc.SpendVtxos(ctx, vtxosKeys)
	if err != nil {
		return nil, err
	}

	return &arkv1.RegisterPaymentResponse{
		Id: id,
	}, nil
}

func (h *handler) ClaimPayment(ctx context.Context, req *arkv1.ClaimPaymentRequest) (*arkv1.ClaimPaymentResponse, error) {
	receivers, err := parseReceivers(req.GetOutputs())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := h.svc.ClaimVtxos(ctx, req.GetId(), receivers); err != nil {
		return nil, err
	}

	return &arkv1.ClaimPaymentResponse{}, nil
}

func (h *handler) FinalizePayment(ctx context.Context, req *arkv1.FinalizePaymentRequest) (*arkv1.FinalizePaymentResponse, error) {
	forfeitTxs, err := parseTxs(req.GetSignedForfeitTxs())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := h.svc.SignVtxos(ctx, forfeitTxs); err != nil {
		return nil, err
	}

	return &arkv1.FinalizePaymentResponse{}, nil
}

func (h *handler) Faucet(ctx context.Context, req *arkv1.FaucetRequest) (*arkv1.FaucetResponse, error) {
	_, pubkey, _, err := parseAddress(req.GetAddress())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := h.svc.FaucetVtxos(ctx, pubkey); err != nil {
		return nil, err
	}

	return &arkv1.FaucetResponse{}, nil
}

func (h *handler) GetRound(ctx context.Context, req *arkv1.GetRoundRequest) (*arkv1.GetRoundResponse, error) {
	if len(req.GetTxid()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing pool txid")
	}

	round, err := h.svc.GetRoundByTxid(ctx, req.GetTxid())
	if err != nil {
		return nil, err
	}

	return &arkv1.GetRoundResponse{
		Round: &arkv1.Round{
			Id:             round.Id,
			Start:          round.StartingTimestamp,
			End:            round.EndingTimestamp,
			Txid:           round.Txid,
			CongestionTree: castCongestionTree(round.CongestionTree),
		},
	}, nil
}

func (h *handler) GetEventStream(_ *arkv1.GetEventStreamRequest, stream arkv1.ArkService_GetEventStreamServer) error {
	listener := &listener{
		id: uuid.NewString(),
		ch: make(chan *arkv1.GetEventStreamResponse),
	}

	defer h.removeListener(listener.id)
	defer close(listener.ch)

	h.pushListener(listener)

	for {
		select {
		case <-stream.Context().Done():
			return nil

		case ev := <-listener.ch:
			if err := stream.Send(ev); err != nil {
				return err
			}

			switch ev.Event.(type) {
			case *arkv1.GetEventStreamResponse_RoundFinalized, *arkv1.GetEventStreamResponse_RoundFailed:
				if err := stream.Send(ev); err != nil {
					return err
				}
				return nil
			}
		}
	}
}

func (h *handler) ListVtxos(ctx context.Context, req *arkv1.ListVtxosRequest) (*arkv1.ListVtxosResponse, error) {
	hrp, userPubkey, aspPubkey, err := parseAddress(req.GetAddress())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	vtxos, err := h.svc.ListVtxos(ctx, userPubkey)
	if err != nil {
		return nil, err
	}

	return &arkv1.ListVtxosResponse{
		Vtxos: vtxoList(vtxos).toProto(hrp, aspPubkey),
	}, nil
}

func (h *handler) GetInfo(ctx context.Context, req *arkv1.GetInfoRequest) (*arkv1.GetInfoResponse, error) {
	pubkey, lifetime, err := h.svc.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetInfoResponse{
		Pubkey:   pubkey,
		Lifetime: lifetime,
	}, nil
}

func (h *handler) pushListener(l *listener) {
	h.listenersLock.Lock()
	defer h.listenersLock.Unlock()

	h.listeners = append(h.listeners, l)
}

func (h *handler) removeListener(id string) {
	h.listenersLock.Lock()
	defer h.listenersLock.Unlock()

	for i, listener := range h.listeners {
		if listener.id == id {
			h.listeners = append(h.listeners[:i], h.listeners[i+1:]...)
			return
		}
	}
}

// listenToEvents forwards events from the application layer to the set of listeners
func (h *handler) listenToEvents() {
	channel := h.svc.GetEventsChannel(context.Background())
	for event := range channel {
		var ev *arkv1.GetEventStreamResponse

		switch e := event.(type) {
		case domain.RoundFinalizationStarted:
			ev = &arkv1.GetEventStreamResponse{
				Event: &arkv1.GetEventStreamResponse_RoundFinalization{
					RoundFinalization: &arkv1.RoundFinalizationEvent{
						Id:             e.Id,
						PoolPartialTx:  e.PoolTx,
						CongestionTree: castCongestionTree(e.CongestionTree),
						ForfeitTxs:     e.UnsignedForfeitTxs,
					},
				},
			}
		case domain.RoundFinalized:
			ev = &arkv1.GetEventStreamResponse{
				Event: &arkv1.GetEventStreamResponse_RoundFinalized{
					RoundFinalized: &arkv1.RoundFinalizedEvent{
						Id:       e.Id,
						PoolTxid: e.Txid,
					},
				},
			}
		case domain.RoundFailed:
			ev = &arkv1.GetEventStreamResponse{
				Event: &arkv1.GetEventStreamResponse_RoundFailed{
					RoundFailed: &arkv1.RoundFailed{
						Id:     e.Id,
						Reason: e.Err,
					},
				},
			}
		}

		if ev != nil {
			for _, listener := range h.listeners {
				listener.ch <- ev
			}
		}
	}
}

type vtxoList []domain.Vtxo

func (v vtxoList) toProto(hrp string, aspKey *secp256k1.PublicKey) []*arkv1.Vtxo {
	list := make([]*arkv1.Vtxo, 0, len(v))
	for _, vv := range v {
		addr := vv.OnchainAddress
		if vv.Pubkey != "" {
			buf, _ := hex.DecodeString(vv.Pubkey)
			key, _ := secp256k1.ParsePubKey(buf)
			addr, _ = common.EncodeAddress(hrp, key, aspKey)
		}
		list = append(list, &arkv1.Vtxo{
			Outpoint: &arkv1.Input{
				Txid: vv.Txid,
				Vout: vv.VOut,
			},
			Receiver: &arkv1.Output{
				Address: addr,
				Amount:  vv.Amount,
			},
			PoolTxid: vv.PoolTx,
			Spent:    vv.Spent,
		})
	}
	return list
}

// castCongestionTree converts a tree.CongestionTree to a repeated arkv1.TreeLevel
func castCongestionTree(congestionTree tree.CongestionTree) *arkv1.Tree {
	levels := make([]*arkv1.TreeLevel, 0, len(congestionTree))
	for _, level := range congestionTree {
		levelProto := &arkv1.TreeLevel{
			Nodes: make([]*arkv1.Node, 0, len(level)),
		}

		for _, node := range level {
			levelProto.Nodes = append(levelProto.Nodes, &arkv1.Node{
				Txid:       node.Txid,
				Tx:         node.Tx,
				ParentTxid: node.ParentTxid,
			})
		}

		levels = append(levels, levelProto)
	}
	return &arkv1.Tree{
		Levels: levels,
	}
}
