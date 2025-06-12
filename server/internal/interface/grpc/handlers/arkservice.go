package handlers

import (
	"context"
	"encoding/hex"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/server/internal/core/application"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type service interface {
	arkv1.ArkServiceServer
}

type handler struct {
	version string

	svc application.Service

	eventsListenerHandler       *broker[*arkv1.GetEventStreamResponse]
	transactionsListenerHandler *broker[*arkv1.GetTransactionsStreamResponse]
}

func NewHandler(version string, service application.Service) service {
	h := &handler{
		version:                     version,
		svc:                         service,
		eventsListenerHandler:       newBroker[*arkv1.GetEventStreamResponse](),
		transactionsListenerHandler: newBroker[*arkv1.GetTransactionsStreamResponse](),
	}

	go h.listenToEvents()
	go h.listenToTxEvents()

	return h
}

func (h *handler) GetInfo(
	ctx context.Context, req *arkv1.GetInfoRequest,
) (*arkv1.GetInfoResponse, error) {
	info, err := h.svc.GetInfo(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.GetInfoResponse{
		Pubkey:              info.PubKey,
		VtxoTreeExpiry:      info.VtxoTreeExpiry,
		UnilateralExitDelay: info.UnilateralExitDelay,
		BoardingExitDelay:   info.BoardingExitDelay,
		RoundInterval:       info.RoundInterval,
		Network:             info.Network,
		Dust:                int64(info.Dust),
		ForfeitAddress:      info.ForfeitAddress,
		MarketHour: &arkv1.MarketHour{
			NextStartTime: info.NextMarketHour.StartTime.Unix(),
			NextEndTime:   info.NextMarketHour.EndTime.Unix(),
			Period:        int64(info.NextMarketHour.Period.Seconds()),
			RoundInterval: int64(info.NextMarketHour.RoundInterval.Seconds()),
		},
		Version:       h.version,
		UtxoMinAmount: info.UtxoMinAmount,
		UtxoMaxAmount: info.UtxoMaxAmount,
		VtxoMinAmount: info.VtxoMinAmount,
		VtxoMaxAmount: info.VtxoMaxAmount,
	}, nil
}

func (h *handler) RegisterIntent(
	ctx context.Context, req *arkv1.RegisterIntentRequest,
) (*arkv1.RegisterIntentResponse, error) {
	signature, message, err := parseIntent(req.GetIntent())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	intentId, err := h.svc.RegisterIntent(ctx, *signature, *message)
	if err != nil {
		return nil, err
	}

	return &arkv1.RegisterIntentResponse{IntentId: intentId}, nil
}

func (h *handler) DeleteIntent(
	ctx context.Context, req *arkv1.DeleteIntentRequest,
) (*arkv1.DeleteIntentResponse, error) {
	signature, message, err := parseDeleteIntent(req.GetProof())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid BIP0322 signature")
	}

	if err := h.svc.DeleteIntentsByProof(ctx, *signature, *message); err != nil {
		return nil, err
	}

	return &arkv1.DeleteIntentResponse{}, nil
}

func (h *handler) ConfirmRegistration(
	ctx context.Context, req *arkv1.ConfirmRegistrationRequest,
) (*arkv1.ConfirmRegistrationResponse, error) {
	intentId := req.GetIntentId()
	if len(intentId) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing intent id")
	}

	if err := h.svc.ConfirmRegistration(ctx, intentId); err != nil {
		return nil, err
	}

	return &arkv1.ConfirmRegistrationResponse{}, nil
}

func (h *handler) SubmitTreeNonces(
	ctx context.Context, req *arkv1.SubmitTreeNoncesRequest,
) (*arkv1.SubmitTreeNoncesResponse, error) {
	batchId, err := parseBatchId(req.GetBatchId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	pubkey, err := parseECPubkey(req.GetPubkey())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	nonces, err := parseNonces(req.GetTreeNonces())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := h.svc.RegisterCosignerNonces(ctx, pubkey, nonces, batchId); err != nil {
		return nil, err
	}

	return &arkv1.SubmitTreeNoncesResponse{}, nil
}

func (h *handler) SubmitTreeSignatures(
	ctx context.Context, req *arkv1.SubmitTreeSignaturesRequest,
) (*arkv1.SubmitTreeSignaturesResponse, error) {
	batchId, err := parseBatchId(req.GetBatchId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	pubkey, err := parseECPubkey(req.GetPubkey())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	signatures, err := parseSignatures(req.GetTreeSignatures())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := h.svc.RegisterCosignerSignatures(ctx, pubkey, signatures, batchId); err != nil {
		return nil, err
	}

	return &arkv1.SubmitTreeSignaturesResponse{}, nil
}

func (h *handler) SubmitSignedForfeitTxs(
	ctx context.Context, req *arkv1.SubmitSignedForfeitTxsRequest,
) (*arkv1.SubmitSignedForfeitTxsResponse, error) {
	forfeitTxs := req.GetSignedForfeitTxs()
	commitmentTx := req.GetSignedCommitmentTx()

	if len(forfeitTxs) > 0 {
		if err := h.svc.SignVtxos(ctx, forfeitTxs); err != nil {
			return nil, err
		}
	}

	if len(commitmentTx) > 0 {
		if err := h.svc.SignCommitmentTx(ctx, commitmentTx); err != nil {
			return nil, err
		}
	}

	return &arkv1.SubmitSignedForfeitTxsResponse{}, nil
}

func (h *handler) GetEventStream(
	_ *arkv1.GetEventStreamRequest, stream arkv1.ArkService_GetEventStreamServer,
) error {
	listener := &listener[*arkv1.GetEventStreamResponse]{
		id: uuid.NewString(),
		ch: make(chan *arkv1.GetEventStreamResponse),
	}

	h.eventsListenerHandler.pushListener(listener)
	defer h.eventsListenerHandler.removeListener(listener.id)
	defer close(listener.ch)

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

func (h *handler) SubmitTx(
	ctx context.Context, req *arkv1.SubmitTxRequest,
) (*arkv1.SubmitTxResponse, error) {
	virtualTx, err := parseVirtualTx(req.GetSignedVirtualTx())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	checkpointTxs, err := parseCheckpointTxs(req.GetCheckpointTxs())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	virtualTxid, signedVirtualTx, signedCheckpoints, err := h.svc.SubmitTx(ctx, checkpointTxs, virtualTx)
	if err != nil {
		return nil, err
	}

	return &arkv1.SubmitTxResponse{
		Txid:                virtualTxid,
		FinalVirtualTx:      signedVirtualTx,
		SignedCheckpointTxs: signedCheckpoints,
	}, nil
}

func (h *handler) FinalizeTx(
	ctx context.Context, req *arkv1.FinalizeTxRequest,
) (*arkv1.FinalizeTxResponse, error) {
	txid, err := parseTxid(req.GetTxid())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	checkpointTxs, err := parseCheckpointTxs(req.GetFinalCheckpointTxs())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := h.svc.FinalizeTx(ctx, txid, checkpointTxs); err != nil {
		return nil, err
	}

	return &arkv1.FinalizeTxResponse{}, nil
}

func (h *handler) GetTransactionsStream(
	_ *arkv1.GetTransactionsStreamRequest,
	stream arkv1.ArkService_GetTransactionsStreamServer,
) error {
	listener := &listener[*arkv1.GetTransactionsStreamResponse]{
		id: uuid.NewString(),
		ch: make(chan *arkv1.GetTransactionsStreamResponse),
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
	for events := range channel {
		evs := make([]*arkv1.GetEventStreamResponse, 0, len(events))

		for _, event := range events {
			switch e := event.(type) {
			case domain.RoundFinalizationStarted:
				evs = append(evs, &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_BatchFinalization{
						BatchFinalization: &arkv1.BatchFinalizationEvent{
							Id:              e.Id,
							CommitmentTx:    e.RoundTx,
							ConnectorsIndex: connectorsIndex(e.ConnectorsIndex).toProto(),
						},
					},
				})
			case application.RoundFinalized:
				evs = append(evs, &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_BatchFinalized{
						BatchFinalized: &arkv1.BatchFinalizedEvent{
							Id:             e.Id,
							CommitmentTxid: e.Txid,
						},
					},
				})
			case domain.RoundFailed:
				evs = append(evs, &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_BatchFailed{
						BatchFailed: &arkv1.BatchFailed{
							Id:     e.Id,
							Reason: e.Err,
						},
					},
				})
			case application.BatchStarted:
				hashes := make([]string, 0, len(e.IntentIdsHashes))
				for _, hash := range e.IntentIdsHashes {
					hashes = append(hashes, hex.EncodeToString(hash[:]))
				}

				evs = append(evs, &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_BatchStarted{
						BatchStarted: &arkv1.BatchStartedEvent{
							Id:             e.Id,
							IntentIdHashes: hashes,
							BatchExpiry:    int64(e.BatchExpiry),
							ForfeitAddress: e.ForfeitAddress,
						},
					},
				})
			case application.RoundSigningStarted:
				evs = append(evs, &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_TreeSigningStarted{
						TreeSigningStarted: &arkv1.TreeSigningStartedEvent{
							Id:                   e.Id,
							UnsignedCommitmentTx: e.UnsignedRoundTx,
							CosignersPubkeys:     e.CosignersPubkeys,
						},
					},
				})
			case application.RoundSigningNoncesGenerated:
				serialized, err := e.SerializeNonces()
				if err != nil {
					logrus.WithError(err).Error("failed to serialize nonces")
					continue
				}

				evs = append(evs, &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_TreeNoncesAggregated{
						TreeNoncesAggregated: &arkv1.TreeNoncesAggregatedEvent{
							Id:         e.Id,
							TreeNonces: serialized,
						},
					},
				})
			case application.BatchTree:
				evs = append(evs, &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_TreeTx{
						TreeTx: &arkv1.TreeTxEvent{
							Id:         e.Id,
							Topic:      e.Topic,
							BatchIndex: e.BatchIndex,
							TreeTx: &arkv1.Node{
								Txid:       e.Node.Txid,
								Tx:         e.Node.Tx,
								ParentTxid: e.Node.ParentTxid,
								Level:      e.Node.Level,
								LevelIndex: e.Node.LevelIndex,
								Leaf:       e.Node.Leaf,
							},
						},
					},
				})
			case application.BatchTreeSignature:
				evs = append(evs, &arkv1.GetEventStreamResponse{
					Event: &arkv1.GetEventStreamResponse_TreeSignature{
						TreeSignature: &arkv1.TreeSignatureEvent{
							Id:         e.Id,
							Topic:      e.Topic,
							BatchIndex: e.BatchIndex,
							Level:      e.Level,
							LevelIndex: e.LevelIndex,
							Signature:  e.Signature,
						},
					},
				})
			}
		}

		// forward all events in the same routine in order to preserve the ordering
		if len(evs) > 0 {
			logrus.Debugf("forwarding event to %d listeners", len(h.eventsListenerHandler.listeners))
			for _, l := range h.eventsListenerHandler.listeners {
				go func(l *listener[*arkv1.GetEventStreamResponse]) {
					for _, ev := range evs {
						l.ch <- ev
					}
				}(l)
			}
		}
	}

}

func (h *handler) listenToTxEvents() {
	eventsCh := h.svc.GetTransactionEventsChannel(context.Background())
	for event := range eventsCh {
		var txEvent *arkv1.GetTransactionsStreamResponse

		switch event.Type() {
		case application.CommitmentTransaction:
			txEvent = &arkv1.GetTransactionsStreamResponse{
				Tx: &arkv1.GetTransactionsStreamResponse_CommitmentTx{
					CommitmentTx: roundTxEvent(event.(application.CommitmentTransactionEvent)).toProto(),
				},
			}
		case application.VirtualTransaction:
			txEvent = &arkv1.GetTransactionsStreamResponse{
				Tx: &arkv1.GetTransactionsStreamResponse_VirtualTx{
					VirtualTx: redeemTxEvent(event.(application.VirtualTransactionEvent)).toProto(),
				},
			}
		}

		if txEvent != nil {
			logrus.Debugf("forwarding event to %d listeners", len(h.transactionsListenerHandler.listeners))
			for _, l := range h.transactionsListenerHandler.listeners {
				go func(l *listener[*arkv1.GetTransactionsStreamResponse]) {
					l.ch <- txEvent
				}(l)
			}
		}
	}
}
