package handlers

import (
	"context"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/internal/core/application"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/vulpemventures/go-elements/psetv2"
)

type handler struct {
	svc         application.Service
	repoManager ports.RepoManager
}

func NewHandler(service application.Service, repoManager ports.RepoManager) arkv1.ArkServiceServer {
	return &handler{
		svc:         service,
		repoManager: repoManager,
	}
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
	forfeits := make(map[string]string)

	for _, b64 := range req.GetSignedForfeits() {
		pset, err := psetv2.NewPsetFromBase64(b64)
		if err != nil {
			return nil, err
		}

		unsignedTx, err := pset.UnsignedTx()
		if err != nil {
			return nil, err
		}

		forfeits[unsignedTx.TxHash().String()] = b64
	}

	err := h.svc.SignVtxos(ctx, forfeits)
	if err != nil {
		return nil, err
	}

	return &arkv1.FinalizePaymentResponse{}, nil
}

func (h *handler) GetRound(ctx context.Context, req *arkv1.GetRoundRequest) (*arkv1.GetRoundResponse, error) {
	txid := req.GetTxid()
	round, err := h.repoManager.Rounds().GetRoundWithTxid(ctx, txid)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetRoundResponse{
		Round: castRound(round),
	}, nil
}

func (h *handler) ListRounds(ctx context.Context, req *arkv1.ListRoundsRequest) (*arkv1.ListRoundsResponse, error) {
	rounds := make([]*domain.Round, 0)
	for _, id := range req.GetIds() {
		round, err := h.repoManager.Rounds().GetRoundWithId(ctx, id)
		if err != nil {
			return nil, err
		}
		rounds = append(rounds, round)
	}

	return &arkv1.ListRoundsResponse{
		Rounds: castRounds(rounds),
	}, nil
}

func (h *handler) GetEventStream(req *arkv1.GetEventStreamRequest, stream arkv1.ArkService_GetEventStreamServer) error {
	roundID := req.GetId()
	timer := time.NewTimer(5 * time.Second)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-timer.C:
			round, err := h.repoManager.Rounds().GetRoundWithId(stream.Context(), roundID)
			if err != nil {
				return err
			}
			events := round.Changes
			for _, event := range events {
				switch e := event.(type) {
				case domain.RoundFinalizationStarted:
					grpcEvent := arkv1.GetEventStreamResponse_RoundFinalization{
						RoundFinalization: &arkv1.RoundFinalizationEvent{
							Id:             e.Id,
							CongestionTree: e.CongestionTree,
							PoolPartialTx:  e.PoolTx,
							ForfeitTxs:     nil, // TODO get forfeit associated with the user payment
						},
					}

					err := stream.Send(&arkv1.GetEventStreamResponse{
						Event: &grpcEvent,
					})
					if err != nil {
						return err
					}
				case domain.RoundFinalized:
					grpcEvent := arkv1.GetEventStreamResponse_RoundFinalized{
						RoundFinalized: &arkv1.RoundFinalizedEvent{
							Id:       e.Id,
							PoolTxid: e.Txid,
						},
					}
					err := stream.Send(&arkv1.GetEventStreamResponse{
						Event: &grpcEvent,
					})
					if err != nil {
						return err
					}
				default:
					continue
				}
				timer.Reset(5 * time.Second)
			}
		}
	}

}

func castRounds(rounds []*domain.Round) []*arkv1.Round {
	arkRounds := make([]*arkv1.Round, 0, len(rounds))
	for _, r := range rounds {
		arkRounds = append(arkRounds, castRound(r))
	}
	return arkRounds
}

func castRound(round *domain.Round) *arkv1.Round {
	return &arkv1.Round{
		Start: round.StartingTimestamp,
		End:   round.EndingTimestamp,
		Txid:  round.Txid,
	}
}
