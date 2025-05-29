package handlers

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/bip322"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/application"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type service interface {
	arkv1.ArkServiceServer
	arkv1.ExplorerServiceServer
}

type handler struct {
	version string

	svc application.Service

	eventsListenerHandler       *listenerHanlder[*arkv1.GetEventStreamResponse]
	transactionsListenerHandler *listenerHanlder[*arkv1.GetTransactionsStreamResponse]
	addressSubsHandler          *listenerHanlder[*arkv1.SubscribeForAddressResponse]

	stopCh                  <-chan struct{}
	stopRoundEventsCh       chan struct{}
	stopTransactionEventsCh chan struct{}
	stopAddressEventsCh     chan struct{}
}

func NewHandler(version string, service application.Service, stopCh <-chan struct{}) service {
	h := &handler{
		version:                     version,
		svc:                         service,
		eventsListenerHandler:       newListenerHandler[*arkv1.GetEventStreamResponse](),
		transactionsListenerHandler: newListenerHandler[*arkv1.GetTransactionsStreamResponse](),
		addressSubsHandler:          newListenerHandler[*arkv1.SubscribeForAddressResponse](),
		stopCh:                      stopCh,
		stopRoundEventsCh:           make(chan struct{}, 1),
		stopTransactionEventsCh:     make(chan struct{}, 1),
		stopAddressEventsCh:         make(chan struct{}, 1),
	}

	go h.listenToStop()
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

	addr, tapscripts, err := h.svc.GetBoardingAddress(ctx, userPubkey)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetBoardingAddressResponse{
		Address: addr,
		TaprootTree: &arkv1.Tapscripts{
			Scripts: tapscripts,
		},
	}, nil
}

func (h *handler) RegisterIntent(
	ctx context.Context, req *arkv1.RegisterIntentRequest,
) (*arkv1.RegisterIntentResponse, error) {
	bip322Signature := req.GetBip322Signature()

	if bip322Signature == nil {
		return nil, status.Error(codes.InvalidArgument, "missing inputs")
	}

	signature, err := bip322.DecodeSignature(bip322Signature.GetSignature())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid BIP0322 signature")
	}

	intentMessage := bip322Signature.GetMessage()

	if len(intentMessage) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing message")
	}

	var message tree.IntentMessage
	if err := message.Decode(intentMessage); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid BIP0322 message")
	}

	requestID, err := h.svc.RegisterIntent(ctx, *signature, message)
	if err != nil {
		return nil, err
	}

	return &arkv1.RegisterIntentResponse{
		RequestId: requestID,
	}, nil
}

func (h *handler) DeleteIntent(
	ctx context.Context, req *arkv1.DeleteIntentRequest,
) (*arkv1.DeleteIntentResponse, error) {
	requestID := req.GetRequestId()
	bip322Signature := req.GetBip322Signature()

	if requestID != "" {
		if err := h.svc.DeleteTxRequests(ctx, requestID); err != nil {
			return nil, err
		}
		return &arkv1.DeleteIntentResponse{}, nil
	}

	if bip322Signature == nil {
		return nil, status.Error(codes.InvalidArgument, "missing request id or bip322 signature")
	}

	signature, err := bip322.DecodeSignature(bip322Signature.GetSignature())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid BIP0322 signature")
	}

	intentMessage := bip322Signature.GetMessage()
	if len(intentMessage) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing BIP0322 message")
	}

	var message tree.IntentMessage
	if err := message.Decode(intentMessage); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid BIP0322 message")
	}

	if err := h.svc.DeleteTxRequestsByProof(ctx, *signature, message); err != nil {
		return nil, err
	}

	return &arkv1.DeleteIntentResponse{}, nil
}

func (h *handler) RegisterInputsForNextRound(
	ctx context.Context, req *arkv1.RegisterInputsForNextRoundRequest,
) (*arkv1.RegisterInputsForNextRoundResponse, error) {
	vtxosInputs := req.GetInputs()

	if len(vtxosInputs) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing inputs")
	}

	inputs, err := parseInputs(vtxosInputs)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	requestID, err := h.svc.SpendVtxos(ctx, inputs)
	if err != nil {
		return nil, err
	}

	return &arkv1.RegisterInputsForNextRoundResponse{
		RequestId: requestID,
	}, nil
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

func (h *handler) RegisterOutputsForNextRound(
	ctx context.Context, req *arkv1.RegisterOutputsForNextRoundRequest,
) (*arkv1.RegisterOutputsForNextRoundResponse, error) {
	receivers, err := parseReceivers(req.GetOutputs())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	musig2Data := req.GetMusig2()
	var musig2 *tree.Musig2
	if musig2Data != nil {
		signingType := tree.SignBranch
		if musig2Data.SigningAll {
			signingType = tree.SignAll
		}
		musig2 = &tree.Musig2{
			CosignersPublicKeys: musig2Data.GetCosignersPublicKeys(),
			SigningType:         signingType,
		}
	}

	if err := h.svc.ClaimVtxos(ctx, req.GetRequestId(), receivers, musig2); err != nil {
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

	cosignerPubkey, err := secp256k1.ParsePubKey(pubkeyBytes)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid cosigner public key")
	}

	if err := h.svc.RegisterCosignerNonces(
		ctx, roundID, cosignerPubkey, encodedNonces,
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

	cosignerPubkey, err := secp256k1.ParsePubKey(pubkeyBytes)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid cosigner public key")
	}

	if err := h.svc.RegisterCosignerSignatures(
		ctx, roundID, cosignerPubkey, encodedSignatures,
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

	if len(forfeitTxs) > 0 {
		if err := h.svc.SignVtxos(ctx, forfeitTxs); err != nil {
			return nil, err
		}
	}

	if len(roundTx) > 0 {
		if err := h.svc.SignRoundTx(ctx, roundTx); err != nil {
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
		case <-h.stopRoundEventsCh:
			return nil
		case <-stream.Context().Done():
			return nil
		case ev := <-listener.ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

func (h *handler) SubmitOffchainTx(
	ctx context.Context, req *arkv1.SubmitOffchainTxRequest,
) (*arkv1.SubmitOffchainTxResponse, error) {
	if req.GetVirtualTx() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing virtual tx")
	}

	if len(req.GetCheckpointTxs()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing checkpoint txs")
	}

	signedCheckpoints, signedVirtualTx, virtualTxid, err := h.svc.SubmitOffchainTx(
		ctx, req.GetCheckpointTxs(), req.GetVirtualTx(),
	)
	if err != nil {
		return nil, err
	}

	return &arkv1.SubmitOffchainTxResponse{
		SignedVirtualTx:     signedVirtualTx,
		Txid:                virtualTxid,
		SignedCheckpointTxs: signedCheckpoints,
	}, nil
}

func (h *handler) FinalizeOffchainTx(
	ctx context.Context, req *arkv1.FinalizeOffchainTxRequest,
) (*arkv1.FinalizeOffchainTxResponse, error) {
	if req.GetTxid() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing txid")
	}

	if len(req.GetCheckpointTxs()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing checkpoint txs")
	}

	if err := h.svc.FinalizeOffchainTx(ctx, req.GetTxid(), req.GetCheckpointTxs()); err != nil {
		return nil, err
	}

	return &arkv1.FinalizeOffchainTxResponse{}, nil
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
				RoundTx:    round.CommitmentTx,
				VtxoTree:   vtxoTree(round.VtxoTree).toProto(),
				ForfeitTxs: forfeitTxs(round.ForfeitTxs).toProto(),
				Connectors: vtxoTree(round.Connectors).toProto(),
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
			RoundTx:    round.CommitmentTx,
			VtxoTree:   vtxoTree(round.VtxoTree).toProto(),
			ForfeitTxs: forfeitTxs(round.ForfeitTxs).toProto(),
			Connectors: vtxoTree(round.Connectors).toProto(),
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
			RoundTx:    round.CommitmentTx,
			VtxoTree:   vtxoTree(round.VtxoTree).toProto(),
			ForfeitTxs: forfeitTxs(round.ForfeitTxs).toProto(),
			Connectors: vtxoTree(round.Connectors).toProto(),
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
		case <-h.stopTransactionEventsCh:
			return nil
		case <-stream.Context().Done():
			return nil
		case ev := <-listener.ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

func (h *handler) SubscribeForAddress(
	req *arkv1.SubscribeForAddressRequest, stream arkv1.ExplorerService_SubscribeForAddressServer,
) error {
	vtxoScript, err := parseArkAddress(req.GetAddress())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	listener := &listener[*arkv1.SubscribeForAddressResponse]{
		id: fmt.Sprintf("%s:%s", uuid.NewString(), vtxoScript),
		ch: make(chan *arkv1.SubscribeForAddressResponse),
	}

	h.addressSubsHandler.pushListener(listener)

	defer func() {
		h.addressSubsHandler.removeListener(listener.id)
		close(listener.ch)
	}()

	for {
		select {
		case <-h.stopAddressEventsCh:
			return nil
		case <-stream.Context().Done():
			return nil
		case ev := <-listener.ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

func (h *handler) listenToStop() {
	<-h.stopCh
	h.stopRoundEventsCh <- struct{}{}
	h.stopTransactionEventsCh <- struct{}{}
	h.stopAddressEventsCh <- struct{}{}

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
						Id:              e.Id,
						RoundTx:         e.RoundTx,
						VtxoTree:        vtxoTree(e.VtxoTree).toProto(),
						Connectors:      vtxoTree(e.Connectors).toProto(),
						ConnectorsIndex: connectorsIndex(e.ConnectorsIndex).toProto(),
					},
				},
			}
		case domain.RoundFinalized:
			ev = &arkv1.GetEventStreamResponse{
				Event: &arkv1.GetEventStreamResponse_RoundFinalized{
					RoundFinalized: &arkv1.RoundFinalizedEvent{
						Id:        e.Id,
						RoundTxid: e.Txid,
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
		case application.BatchStarted:
			hashes := make([]string, 0, len(e.IntentIdsHashes))
			for _, hash := range e.IntentIdsHashes {
				hashes = append(hashes, hex.EncodeToString(hash[:]))
			}

			ev = &arkv1.GetEventStreamResponse{
				Event: &arkv1.GetEventStreamResponse_BatchStarted{
					BatchStarted: &arkv1.BatchStartedEvent{
						Id:              e.Id,
						IntentIdsHashes: hashes,
						BatchExpiry:     int64(e.BatchExpiry),
						ForfeitAddress:  e.ForfeitAddress,
					},
				},
			}
		case application.RoundSigningStarted:
			ev = &arkv1.GetEventStreamResponse{
				Event: &arkv1.GetEventStreamResponse_RoundSigning{
					RoundSigning: &arkv1.RoundSigningEvent{
						Id:               e.Id,
						UnsignedVtxoTree: vtxoTree(e.UnsignedVtxoTree).toProto(),
						UnsignedRoundTx:  e.UnsignedRoundTx,
						CosignersPubkeys: e.CosignersPubkeys,
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
		case application.RoundTransaction:
			txEvent = &arkv1.GetTransactionsStreamResponse{
				Tx: &arkv1.GetTransactionsStreamResponse_Round{
					Round: roundTxEvent(event.(application.RoundTransactionEvent)).toProto(),
				},
			}
		case application.RedeemTransaction:
			txEvent = &arkv1.GetTransactionsStreamResponse{
				Tx: &arkv1.GetTransactionsStreamResponse_Redeem{
					Redeem: redeemTxEvent(event.(application.RedeemTransactionEvent)).toProto(),
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

			if len(h.addressSubsHandler.listeners) > 0 {
				allSpendableVtxos := make(map[string][]*arkv1.Vtxo)
				allSpentVtxos := make(map[string][]*arkv1.Vtxo)
				if txEvent.GetRedeem() != nil {
					for _, vtxo := range txEvent.GetRedeem().GetSpendableVtxos() {
						allSpendableVtxos[vtxo.Pubkey] = append(allSpendableVtxos[vtxo.Pubkey], vtxo)
					}
					for _, vtxo := range txEvent.GetRedeem().GetSpentVtxos() {
						allSpentVtxos[vtxo.Pubkey] = append(allSpentVtxos[vtxo.Pubkey], vtxo)
					}
				} else {
					for _, vtxo := range txEvent.GetRound().GetSpendableVtxos() {
						allSpendableVtxos[vtxo.Pubkey] = append(allSpendableVtxos[vtxo.Pubkey], vtxo)
					}
					for _, vtxo := range txEvent.GetRound().GetSpentVtxos() {
						allSpentVtxos[vtxo.Pubkey] = append(allSpentVtxos[vtxo.Pubkey], vtxo)
					}
				}

				for _, l := range h.addressSubsHandler.listeners {
					vtxoScript := strings.Split(l.id, ":")[1]
					spendableVtxos := allSpendableVtxos[vtxoScript]
					spentVtxos := allSpentVtxos[vtxoScript]
					if len(spendableVtxos) > 0 || len(spentVtxos) > 0 {
						l.ch <- &arkv1.SubscribeForAddressResponse{
							NewVtxos:   spendableVtxos,
							SpentVtxos: spentVtxos,
						}
					}
				}
			}
		}
	}
}

type listener[T any] struct {
	id string
	ch chan T
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
