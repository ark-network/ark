package handlers

import (
	"context"
	"sync"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/internal/core/application"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
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

func NewHandler(service application.Service, repoManager ports.RepoManager) arkv1.ArkServiceServer {
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
	receivers := make([]domain.Receiver, 0, len(req.GetOutputs()))
	for _, output := range req.GetOutputs() {
		receivers = append(receivers, domain.Receiver{
			Pubkey: output.GetPubkey(),
			Amount: output.GetAmount(),
		})
	}

	err := h.svc.ClaimVtxos(ctx, req.GetId(), receivers)
	if err != nil {
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
	pubkey, err := parseAddress(req.GetAddress())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := h.svc.FaucetVtxos(ctx, pubkey); err != nil {
		return nil, err
	}

	return &arkv1.FaucetResponse{}, nil
}

func (h *handler) GetRound(ctx context.Context, req *arkv1.GetRoundRequest) (*arkv1.GetRoundResponse, error) {
	if req.GetTxid() != "" {
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
			CongestionTree: congestionTreeAsList(round.CongestionTree),
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
				return nil
			}
		}
	}
}

func (h *handler) ListVtxos(ctx context.Context, req *arkv1.ListVtxosRequest) (*arkv1.ListVtxosResponse, error) {
	pubkey, err := parseAddress(req.GetAddress())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	vtxos, err := h.svc.ListVtxos(ctx, pubkey)
	if err != nil {
		return nil, err
	}

	return &arkv1.ListVtxosResponse{
		Vtxos: vtxoList(vtxos).toProto(),
	}, nil
}

func (h *handler) GetPubkey(ctx context.Context, req *arkv1.GetPubkeyRequest) (*arkv1.GetPubkeyResponse, error) {
	pubkey, err := h.svc.GetPubkey(ctx)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetPubkeyResponse{
		Pubkey: pubkey,
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
						CongestionTree: congestionTreeAsList(e.CongestionTree),
						ForfeitTxs:     nil, // TODO: add forfeit txs
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
						Reason: e.Err.Error(),
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

func (v vtxoList) toProto() []*arkv1.Vtxo {
	list := make([]*arkv1.Vtxo, 0, len(v))
	for _, vv := range v {
		list = append(list, &arkv1.Vtxo{
			Outpoint: &arkv1.Input{
				Txid: vv.Txid,
				Vout: vv.VOut,
			},
			Receiver: &arkv1.Output{
				Pubkey: vv.Pubkey,
				Amount: vv.Amount,
			},
			Spent: vv.Spent,
		})
	}
	return list
}

func congestionTreeAsList(tree domain.CongestionTree) []string {
	congestionTreeAsList := make([]string, 0)
	for _, level := range tree {
		for _, node := range level {
			congestionTreeAsList = append(congestionTreeAsList, node.Txid)
		}
	}
	return congestionTreeAsList
}
