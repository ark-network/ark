package handlers

import (
	"context"
	"encoding/hex"
	"sync"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/server/internal/core/application"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type handler struct {
	svc application.Service

	eventsListenerHandler       *listenerHanlder[*arkv1.GetEventStreamResponse]
	transactionsListenerHandler *listenerHanlder[*arkv1.GetTransactionsStreamResponse]
}

func NewHandler(service application.Service) arkv1.ArkServiceServer {
	h := &handler{
		svc:                         service,
		eventsListenerHandler:       newListenerHandler[*arkv1.GetEventStreamResponse](),
		transactionsListenerHandler: newListenerHandler[*arkv1.GetTransactionsStreamResponse](),
	}

	go h.listenToEvents()
	go h.listenToPaymentEvents()

	return h
}

func (h *handler) GetInfo(
	ctx context.Context, req *arkv1.GetInfoRequest,
) (*arkv1.GetInfoResponse, error) {
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
		ForfeitAddress:             info.ForfeitAddress,
	}, nil
}

func (h *handler) GetBoardingAddress(
	ctx context.Context, req *arkv1.GetBoardingAddressRequest,
) (*arkv1.GetBoardingAddressResponse, error) {
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

func (h *handler) RegisterInputsForNextRound(
	ctx context.Context, req *arkv1.RegisterInputsForNextRoundRequest,
) (*arkv1.RegisterInputsForNextRoundResponse, error) {
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

	return &arkv1.RegisterInputsForNextRoundResponse{
		Id: id,
	}, nil
}

func (h *handler) RegisterOutputsForNextRound(
	ctx context.Context, req *arkv1.RegisterOutputsForNextRoundRequest,
) (*arkv1.RegisterOutputsForNextRoundResponse, error) {
	receivers, err := parseReceivers(req.GetOutputs())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := h.svc.ClaimVtxos(ctx, req.GetId(), receivers); err != nil {
		return nil, err
	}

	return &arkv1.RegisterOutputsForNextRoundResponse{}, nil
}

func (h *handler) SubmitTreeNonces(
	ctx context.Context, req *arkv1.SubmitTreeNoncesRequest,
) (*arkv1.SubmitTreeNoncesResponse, error) {
	pubkey := req.GetPubkey()
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

	if err := h.svc.RegisterCosignerNonces(
		ctx, roundID, cosignerPublicKey, encodedNonces,
	); err != nil {
		return nil, err
	}

	return &arkv1.SubmitTreeNoncesResponse{}, nil
}

func (h *handler) SubmitTreeSignatures(
	ctx context.Context, req *arkv1.SubmitTreeSignaturesRequest,
) (*arkv1.SubmitTreeSignaturesResponse, error) {
	roundID := req.GetRoundId()
	pubkey := req.GetPubkey()
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

	if err := h.svc.RegisterCosignerSignatures(
		ctx, roundID, cosignerPublicKey, encodedSignatures,
	); err != nil {
		return nil, err
	}

	return &arkv1.SubmitTreeSignaturesResponse{}, nil
}

func (h *handler) SubmitSignedForfeitTxs(
	ctx context.Context, req *arkv1.SubmitSignedForfeitTxsRequest,
) (*arkv1.SubmitSignedForfeitTxsResponse, error) {
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

	return &arkv1.SubmitSignedForfeitTxsResponse{}, nil
}

func (h *handler) GetEventStream(
	_ *arkv1.GetEventStreamRequest, stream arkv1.ArkService_GetEventStreamServer,
) error {
	doneCh := make(chan struct{})

	listener := &listener[*arkv1.GetEventStreamResponse]{
		id:   uuid.NewString(),
		done: doneCh,
		ch:   make(chan *arkv1.GetEventStreamResponse),
	}

	h.eventsListenerHandler.pushListener(listener)
	defer h.eventsListenerHandler.removeListener(listener.id)
	defer close(listener.ch)
	defer close(doneCh)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-doneCh:
			return nil
		case ev := <-listener.ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

func (h *handler) Ping(
	ctx context.Context, req *arkv1.PingRequest,
) (*arkv1.PingResponse, error) {
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
					Id:              e.Id,
					RoundTx:         e.RoundTx,
					VtxoTree:        congestionTree(e.CongestionTree).toProto(),
					Connectors:      e.Connectors,
					MinRelayFeeRate: e.MinRelayFeeRate,
				},
			},
		}
	case domain.RoundFinalized:
		resp = &arkv1.PingResponse{
			Event: &arkv1.PingResponse_RoundFinalized{
				RoundFinalized: &arkv1.RoundFinalizedEvent{
					Id:        e.Id,
					RoundTxid: e.Txid,
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
					UnsignedVtxoTree: congestionTree(e.UnsignedVtxoTree).toProto(),
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

func (h *handler) CreatePayment(
	ctx context.Context, req *arkv1.CreatePaymentRequest,
) (*arkv1.CreatePaymentResponse, error) {
	inputs, err := parseAsyncPaymentInputs(req.GetInputs())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	receivers, err := parseReceivers(req.GetOutputs())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	for _, receiver := range receivers {
		if receiver.Amount <= 0 {
			return nil, status.Error(codes.InvalidArgument, "output amount must be greater than 0")
		}

		if len(receiver.Address) <= 0 {
			return nil, status.Error(codes.InvalidArgument, "missing address")
		}

		if receiver.IsOnchain() {
			return nil, status.Error(codes.InvalidArgument, "onchain outputs are not supported as async payment destination")
		}
	}

	redeemTx, err := h.svc.CreateAsyncPayment(
		ctx, inputs, receivers,
	)
	if err != nil {
		return nil, err
	}

	return &arkv1.CreatePaymentResponse{
		SignedRedeemTx: redeemTx,
	}, nil
}

func (h *handler) CompletePayment(
	ctx context.Context, req *arkv1.CompletePaymentRequest,
) (*arkv1.CompletePaymentResponse, error) {
	if req.GetSignedRedeemTx() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing signed redeem tx")
	}

	if err := h.svc.CompleteAsyncPayment(
		ctx, req.GetSignedRedeemTx(),
	); err != nil {
		return nil, err
	}

	return &arkv1.CompletePaymentResponse{}, nil
}

func (h *handler) GetRound(
	ctx context.Context, req *arkv1.GetRoundRequest,
) (*arkv1.GetRoundResponse, error) {
	if len(req.GetTxid()) <= 0 {
		round, err := h.svc.GetCurrentRound(ctx)
		if err != nil {
			return nil, err
		}

		return &arkv1.GetRoundResponse{
			Round: &arkv1.Round{
				Id:         round.Id,
				Start:      round.StartingTimestamp,
				End:        round.EndingTimestamp,
				RoundTx:    round.UnsignedTx,
				VtxoTree:   congestionTree(round.CongestionTree).toProto(),
				ForfeitTxs: round.ForfeitTxs,
				Connectors: round.Connectors,
				Stage:      stage(round.Stage).toProto(),
			},
		}, nil
	}

	round, err := h.svc.GetRoundByTxid(ctx, req.GetTxid())
	if err != nil {
		return nil, err
	}

	return &arkv1.GetRoundResponse{
		Round: &arkv1.Round{
			Id:         round.Id,
			Start:      round.StartingTimestamp,
			End:        round.EndingTimestamp,
			RoundTx:    round.UnsignedTx,
			VtxoTree:   congestionTree(round.CongestionTree).toProto(),
			ForfeitTxs: round.ForfeitTxs,
			Connectors: round.Connectors,
			Stage:      stage(round.Stage).toProto(),
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
			Id:         round.Id,
			Start:      round.StartingTimestamp,
			End:        round.EndingTimestamp,
			RoundTx:    round.UnsignedTx,
			VtxoTree:   congestionTree(round.CongestionTree).toProto(),
			ForfeitTxs: round.ForfeitTxs,
			Connectors: round.Connectors,
			Stage:      stage(round.Stage).toProto(),
		},
	}, nil
}

func (h *handler) ListVtxos(
	ctx context.Context, req *arkv1.ListVtxosRequest,
) (*arkv1.ListVtxosResponse, error) {
	_, err := parseAddress(req.GetAddress())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	spendableVtxos, spentVtxos, err := h.svc.ListVtxos(ctx, req.GetAddress())
	if err != nil {
		return nil, err
	}

	return &arkv1.ListVtxosResponse{
		SpendableVtxos: vtxoList(spendableVtxos).toProto(),
		SpentVtxos:     vtxoList(spentVtxos).toProto(),
	}, nil
}

func (h *handler) GetTransactionsStream(
	_ *arkv1.GetTransactionsStreamRequest,
	stream arkv1.ArkService_GetTransactionsStreamServer,
) error {
	listener := &listener[*arkv1.GetTransactionsStreamResponse]{
		id:   uuid.NewString(),
		done: make(chan struct{}),
		ch:   make(chan *arkv1.GetTransactionsStreamResponse),
	}

	h.transactionsListenerHandler.pushListener(listener)

	defer func() {
		h.transactionsListenerHandler.removeListener(listener.id)
		close(listener.ch)
	}()

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

// listenToEvents forwards events from the application layer to the set of listeners
func (h *handler) listenToEvents() {
	channel := h.svc.GetEventsChannel(context.Background())
	for event := range channel {
		var ev *arkv1.GetEventStreamResponse
		shouldClose := false

		switch e := event.(type) {
		case domain.RoundFinalizationStarted:
			ev = &arkv1.GetEventStreamResponse{
				Event: &arkv1.GetEventStreamResponse_RoundFinalization{
					RoundFinalization: &arkv1.RoundFinalizationEvent{
						Id:              e.Id,
						RoundTx:         e.RoundTx,
						VtxoTree:        congestionTree(e.CongestionTree).toProto(),
						Connectors:      e.Connectors,
						MinRelayFeeRate: e.MinRelayFeeRate,
					},
				},
			}
		case domain.RoundFinalized:
			shouldClose = true
			ev = &arkv1.GetEventStreamResponse{
				Event: &arkv1.GetEventStreamResponse_RoundFinalized{
					RoundFinalized: &arkv1.RoundFinalizedEvent{
						Id:        e.Id,
						RoundTxid: e.Txid,
					},
				},
			}
		case domain.RoundFailed:
			shouldClose = true
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
				keyStr := hex.EncodeToString(key.SerializeCompressed())
				cosignersKeys = append(cosignersKeys, keyStr)
			}

			ev = &arkv1.GetEventStreamResponse{
				Event: &arkv1.GetEventStreamResponse_RoundSigning{
					RoundSigning: &arkv1.RoundSigningEvent{
						Id:               e.Id,
						CosignersPubkeys: cosignersKeys,
						UnsignedVtxoTree: congestionTree(e.UnsignedVtxoTree).toProto(),
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
			logrus.Debugf("forwarding event to %d listeners", len(h.eventsListenerHandler.listeners))
			for _, l := range h.eventsListenerHandler.listeners {
				go func(l *listener[*arkv1.GetEventStreamResponse]) {
					l.ch <- ev
					if shouldClose {
						l.done <- struct{}{}
					}
				}(l)
			}
		}
	}
}

func (h *handler) listenToPaymentEvents() {
	paymentEventsCh := h.svc.GetTransactionEventsChannel(context.Background())
	for event := range paymentEventsCh {
		var paymentEvent *arkv1.GetTransactionsStreamResponse

		switch event.Type() {
		case application.RoundTransaction:
			paymentEvent = &arkv1.GetTransactionsStreamResponse{
				Tx: &arkv1.GetTransactionsStreamResponse_Round{
					Round: convertRoundPaymentEvent(event.(application.RoundTransactionEvent)),
				},
			}
		case application.RedeemTransaction:
			paymentEvent = &arkv1.GetTransactionsStreamResponse{
				Tx: &arkv1.GetTransactionsStreamResponse_Redeem{
					Redeem: convertAsyncPaymentEvent(event.(application.RedeemTransactionEvent)),
				},
			}
		}

		if paymentEvent != nil {
			logrus.Debugf("forwarding event to %d listeners", len(h.transactionsListenerHandler.listeners))
			for _, l := range h.transactionsListenerHandler.listeners {
				go func(l *listener[*arkv1.GetTransactionsStreamResponse]) {
					l.ch <- paymentEvent
				}(l)
			}
		}
	}
}

func convertRoundPaymentEvent(e application.RoundTransactionEvent) *arkv1.RoundTransaction {
	return &arkv1.RoundTransaction{
		Txid:                 e.RoundTxID,
		SpentVtxos:           vtxoKeyList(e.SpentVtxos).toProto(),
		SpendableVtxos:       vtxoList(e.SpendableVtxos).toProto(),
		ClaimedBoardingUtxos: vtxoKeyList(e.ClaimedBoardingInputs).toProto(),
	}
}

func convertAsyncPaymentEvent(e application.RedeemTransactionEvent) *arkv1.RedeemTransaction {
	return &arkv1.RedeemTransaction{
		Txid:           e.AsyncTxID,
		SpentVtxos:     vtxoKeyList(e.SpentVtxos).toProto(),
		SpendableVtxos: vtxoList(e.SpendableVtxos).toProto(),
	}
}

type listener[T any] struct {
	id   string
	done chan struct{}
	ch   chan T
}

type listenerHanlder[T any] struct {
	lock      *sync.Mutex
	listeners []*listener[T]
}

func newListenerHandler[T any]() *listenerHanlder[T] {
	return &listenerHanlder[T]{
		lock:      &sync.Mutex{},
		listeners: make([]*listener[T], 0),
	}
}

func (h *listenerHanlder[T]) pushListener(l *listener[T]) {
	h.lock.Lock()
	defer h.lock.Unlock()

	h.listeners = append(h.listeners, l)
}

func (h *listenerHanlder[T]) removeListener(id string) {
	h.lock.Lock()
	defer h.lock.Unlock()

	for i, listener := range h.listeners {
		if listener.id == id {
			h.listeners = append(h.listeners[:i], h.listeners[i+1:]...)
			return
		}
	}
}
