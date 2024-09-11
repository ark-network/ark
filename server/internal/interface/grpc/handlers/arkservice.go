package handlers

import (
	"context"
	"encoding/hex"
	"sync"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/application"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
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

func (h *handler) CompletePayment(ctx context.Context, req *arkv1.CompletePaymentRequest) (*arkv1.CompletePaymentResponse, error) {
	if req.GetSignedRedeemTx() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing signed redeem tx")
	}

	if len(req.GetSignedUnconditionalForfeitTxs()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing signed unconditional forfeit txs")
	}

	if err := h.svc.CompleteAsyncPayment(
		ctx, req.GetSignedRedeemTx(), req.GetSignedUnconditionalForfeitTxs(),
	); err != nil {
		return nil, err
	}

	return &arkv1.CompletePaymentResponse{}, nil
}

func (h *handler) CreatePayment(ctx context.Context, req *arkv1.CreatePaymentRequest) (*arkv1.CreatePaymentResponse, error) {
	inputs, err := parseInputs(req.GetInputs())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	receivers, err := parseReceivers(req.GetOutputs())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	redeemTx, unconditionalForfeitTxs, err := h.svc.CreateAsyncPayment(
		ctx, inputs, receivers,
	)
	if err != nil {
		return nil, err
	}

	return &arkv1.CreatePaymentResponse{
		SignedRedeemTx:                 redeemTx,
		UsignedUnconditionalForfeitTxs: unconditionalForfeitTxs,
	}, nil
}

func (h *handler) Ping(ctx context.Context, req *arkv1.PingRequest) (*arkv1.PingResponse, error) {
	if req.GetPaymentId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing payment id")
	}

	lastEvent, err := h.svc.UpdatePaymentStatus(ctx, req.GetPaymentId())
	if err != nil {
		return nil, err
	}

	var resp *arkv1.PingResponse

	switch e := lastEvent.(type) {
	case domain.RoundFinalizationStarted:
		resp = &arkv1.PingResponse{
			Event: &arkv1.PingResponse_RoundFinalization{
				RoundFinalization: &arkv1.RoundFinalizationEvent{
					Id:             e.Id,
					PoolTx:         e.PoolTx,
					CongestionTree: castCongestionTree(e.CongestionTree),
					ForfeitTxs:     e.UnsignedForfeitTxs,
					Connectors:     e.Connectors,
				},
			},
		}
	case domain.RoundFinalized:
		resp = &arkv1.PingResponse{
			Event: &arkv1.PingResponse_RoundFinalized{
				RoundFinalized: &arkv1.RoundFinalizedEvent{
					Id:       e.Id,
					PoolTxid: e.Txid,
				},
			},
		}
	case domain.RoundFailed:
		resp = &arkv1.PingResponse{
			Event: &arkv1.PingResponse_RoundFailed{
				RoundFailed: &arkv1.RoundFailed{
					Id:     e.Id,
					Reason: e.Err,
				},
			},
		}
	case application.RoundSigningStarted:
		cosignersKeys := make([]string, 0, len(e.Cosigners))
		for _, key := range e.Cosigners {
			cosignersKeys = append(cosignersKeys, hex.EncodeToString(key.SerializeCompressed()))
		}

		resp = &arkv1.PingResponse{
			Event: &arkv1.PingResponse_RoundSigning{
				RoundSigning: &arkv1.RoundSigningEvent{
					Id:               e.Id,
					CosignersPubkeys: cosignersKeys,
					UnsignedTree:     castCongestionTree(e.UnsignedVtxoTree),
					UnsignedRoundTx:  e.UnsignedRoundTx,
				},
			},
		}
	case application.RoundSigningNoncesGenerated:
		serialized, err := e.SerializeNonces()
		if err != nil {
			logrus.WithError(err).Error("failed to serialize nonces")
			return nil, status.Error(codes.Internal, "failed to serialize nonces")
		}

		resp = &arkv1.PingResponse{
			Event: &arkv1.PingResponse_RoundSigningNoncesGenerated{
				RoundSigningNoncesGenerated: &arkv1.RoundSigningNoncesGeneratedEvent{
					Id:         e.Id,
					TreeNonces: serialized,
				},
			},
		}
	}

	return resp, nil
}

func (h *handler) RegisterPayment(ctx context.Context, req *arkv1.RegisterPaymentRequest) (*arkv1.RegisterPaymentResponse, error) {
	inputs, err := parseInputs(req.GetInputs())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	id, err := h.svc.SpendVtxos(ctx, inputs)
	if err != nil {
		return nil, err
	}

	pubkey := req.GetEphemeralPubkey()
	if len(pubkey) > 0 {
		if err := h.svc.RegisterCosignerPubkey(ctx, id, pubkey); err != nil {
			return nil, err
		}
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
	forfeitTxs := req.GetSignedForfeitTxs()
	roundTx := req.GetSignedRoundTx()

	if len(forfeitTxs) <= 0 && roundTx == "" {
		return nil, status.Error(codes.InvalidArgument, "missing forfeit txs or round tx")
	}

	if len(forfeitTxs) > 0 {
		if err := h.svc.SignVtxos(ctx, forfeitTxs); err != nil {
			return nil, err
		}
	}

	if roundTx != "" {
		if err := h.svc.SignRoundTx(ctx, roundTx); err != nil {
			return nil, err
		}
	}

	return &arkv1.FinalizePaymentResponse{}, nil
}

func (h *handler) GetRound(ctx context.Context, req *arkv1.GetRoundRequest) (*arkv1.GetRoundResponse, error) {
	if len(req.GetTxid()) <= 0 {
		round, err := h.svc.GetCurrentRound(ctx)
		if err != nil {
			return nil, err
		}

		return &arkv1.GetRoundResponse{
			Round: &arkv1.Round{
				Id:             round.Id,
				Start:          round.StartingTimestamp,
				End:            round.EndingTimestamp,
				PoolTx:         round.UnsignedTx,
				CongestionTree: castCongestionTree(round.CongestionTree),
				ForfeitTxs:     round.ForfeitTxs,
				Connectors:     round.Connectors,
				Stage:          toRoundStage(round.Stage),
			},
		}, nil
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
			PoolTx:         round.UnsignedTx,
			CongestionTree: castCongestionTree(round.CongestionTree),
			ForfeitTxs:     round.ForfeitTxs,
			Connectors:     round.Connectors,
			Stage:          toRoundStage(round.Stage),
		},
	}, nil
}

func (h *handler) GetRoundById(
	ctx context.Context, req *arkv1.GetRoundByIdRequest,
) (*arkv1.GetRoundByIdResponse, error) {
	id := req.GetId()
	if len(id) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing round id")
	}

	round, err := h.svc.GetRoundById(ctx, id)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetRoundByIdResponse{
		Round: &arkv1.Round{
			Id:             round.Id,
			Start:          round.StartingTimestamp,
			End:            round.EndingTimestamp,
			PoolTx:         round.UnsignedTx,
			CongestionTree: castCongestionTree(round.CongestionTree),
			ForfeitTxs:     round.ForfeitTxs,
			Connectors:     round.Connectors,
			Stage:          toRoundStage(round.Stage),
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
		}
	}
}

func (h *handler) ListVtxos(ctx context.Context, req *arkv1.ListVtxosRequest) (*arkv1.ListVtxosResponse, error) {
	_, userPubkey, _, err := parseAddress(req.GetAddress())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	spendableVtxos, spentVtxos, err := h.svc.ListVtxos(ctx, userPubkey)
	if err != nil {
		return nil, err
	}

	return &arkv1.ListVtxosResponse{
		SpendableVtxos: vtxoList(spendableVtxos).toProto(),
		SpentVtxos:     vtxoList(spentVtxos).toProto(),
	}, nil
}

func (h *handler) GetInfo(ctx context.Context, req *arkv1.GetInfoRequest) (*arkv1.GetInfoResponse, error) {
	info, err := h.svc.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetInfoResponse{
		Pubkey:                     info.PubKey,
		RoundLifetime:              info.RoundLifetime,
		UnilateralExitDelay:        info.UnilateralExitDelay,
		RoundInterval:              info.RoundInterval,
		Network:                    info.Network,
		Dust:                       int64(info.Dust),
		BoardingDescriptorTemplate: info.BoardingDescriptorTemplate,
	}, nil
}

func (h *handler) GetBoardingAddress(ctx context.Context, req *arkv1.GetBoardingAddressRequest) (*arkv1.GetBoardingAddressResponse, error) {
	pubkey := req.GetPubkey()
	if pubkey == "" {
		return nil, status.Error(codes.InvalidArgument, "missing pubkey")
	}

	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid pubkey (invalid hex)")
	}

	userPubkey, err := secp256k1.ParsePubKey(pubkeyBytes)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid pubkey (parse error)")
	}

	addr, descriptor, err := h.svc.GetBoardingAddress(ctx, userPubkey)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetBoardingAddressResponse{
		Address:     addr,
		Descriptor_: descriptor,
	}, nil
}

func (h *handler) SendTreeNonces(ctx context.Context, req *arkv1.SendTreeNoncesRequest) (*arkv1.SendTreeNoncesResponse, error) {
	pubkey := req.GetPublicKey()
	encodedNonces := req.GetTreeNonces()
	roundID := req.GetRoundId()

	if len(pubkey) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing cosigner public key")
	}

	if len(encodedNonces) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing tree nonces")
	}

	if len(roundID) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing round id")
	}

	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid cosigner public key")
	}

	cosignerPublicKey, err := secp256k1.ParsePubKey(pubkeyBytes)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid cosigner public key")
	}

	if err := h.svc.RegisterCosignerNonces(ctx, roundID, cosignerPublicKey, encodedNonces); err != nil {
		return nil, err
	}

	return &arkv1.SendTreeNoncesResponse{}, nil
}

func (h *handler) SendTreeSignatures(ctx context.Context, req *arkv1.SendTreeSignaturesRequest) (*arkv1.SendTreeSignaturesResponse, error) {
	roundID := req.GetRoundId()
	pubkey := req.GetPublicKey()
	encodedSignatures := req.GetTreeSignatures()

	if len(pubkey) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing cosigner public key")
	}

	if len(encodedSignatures) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing tree signatures")
	}

	if len(roundID) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing round id")
	}

	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid cosigner public key")
	}

	cosignerPublicKey, err := secp256k1.ParsePubKey(pubkeyBytes)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid cosigner public key")
	}

	if err := h.svc.RegisterCosignerSignatures(ctx, roundID, cosignerPublicKey, encodedSignatures); err != nil {
		return nil, err
	}

	return &arkv1.SendTreeSignaturesResponse{}, nil
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
						PoolTx:         e.PoolTx,
						CongestionTree: castCongestionTree(e.CongestionTree),
						ForfeitTxs:     e.UnsignedForfeitTxs,
						Connectors:     e.Connectors,
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
		case application.RoundSigningStarted:
			cosignersKeys := make([]string, 0, len(e.Cosigners))
			for _, key := range e.Cosigners {
				cosignersKeys = append(cosignersKeys, hex.EncodeToString(key.SerializeCompressed()))
			}

			ev = &arkv1.GetEventStreamResponse{
				Event: &arkv1.GetEventStreamResponse_RoundSigning{
					RoundSigning: &arkv1.RoundSigningEvent{
						Id:               e.Id,
						CosignersPubkeys: cosignersKeys,
						UnsignedTree:     castCongestionTree(e.UnsignedVtxoTree),
						UnsignedRoundTx:  e.UnsignedRoundTx,
					},
				},
			}
		case application.RoundSigningNoncesGenerated:
			serialized, err := e.SerializeNonces()
			if err != nil {
				logrus.WithError(err).Error("failed to serialize nonces")
				continue
			}

			ev = &arkv1.GetEventStreamResponse{
				Event: &arkv1.GetEventStreamResponse_RoundSigningNoncesGenerated{
					RoundSigningNoncesGenerated: &arkv1.RoundSigningNoncesGeneratedEvent{
						Id:         e.Id,
						TreeNonces: serialized,
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
		var pendingData *arkv1.PendingPayment
		if vv.AsyncPayment != nil {
			pendingData = &arkv1.PendingPayment{
				RedeemTx:                vv.AsyncPayment.RedeemTx,
				UnconditionalForfeitTxs: vv.AsyncPayment.UnconditionalForfeitTxs,
			}
		}
		list = append(list, &arkv1.Vtxo{
			Outpoint: &arkv1.Outpoint{
				Txid: vv.Txid,
				Vout: vv.VOut,
			},
			Descriptor_: vv.Descriptor,
			Amount:      vv.Amount,
			PoolTxid:    vv.PoolTx,
			Spent:       vv.Spent,
			ExpireAt:    vv.ExpireAt,
			SpentBy:     vv.SpentBy,
			Swept:       vv.Swept,
			PendingData: pendingData,
			Pending:     pendingData != nil,
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
