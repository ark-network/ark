package handlers

import (
	"context"
	"fmt"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/server/internal/core/application"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type adminHandler struct {
	adminService application.AdminService
	arkService   application.Service

	noteUriPrefix string
}

func NewAdminHandler(
	adminService application.AdminService, arkService application.Service, noteUriPrefix string,
) arkv1.AdminServiceServer {
	return &adminHandler{adminService, arkService, noteUriPrefix}
}

func (a *adminHandler) GetRoundDetails(ctx context.Context, req *arkv1.GetRoundDetailsRequest) (*arkv1.GetRoundDetailsResponse, error) {
	id := req.GetRoundId()
	if len(id) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing round id")
	}

	details, err := a.adminService.GetRoundDetails(ctx, id)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetRoundDetailsResponse{
		RoundId:          details.RoundId,
		CommitmentTxid:   details.TxId,
		ForfeitedAmount:  convertSatsToBTCStr(details.ForfeitedAmount),
		TotalVtxosAmount: convertSatsToBTCStr(details.TotalVtxosAmount),
		TotalExitAmount:  convertSatsToBTCStr(details.TotalExitAmount),
		TotalFeeAmount:   convertSatsToBTCStr(details.FeesAmount),
		InputsVtxos:      details.InputsVtxos,
		OutputsVtxos:     details.OutputsVtxos,
		ExitAddresses:    details.ExitAddresses,
	}, nil
}

func (a *adminHandler) GetRounds(ctx context.Context, req *arkv1.GetRoundsRequest) (*arkv1.GetRoundsResponse, error) {
	startAfter := req.GetAfter()
	startBefore := req.GetBefore()

	if startAfter < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid after (must be >= 0)")
	}

	if startBefore < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid before (must be >= 0)")
	}

	if startAfter >= startBefore {
		return nil, status.Error(codes.InvalidArgument, "invalid range")
	}

	rounds, err := a.adminService.GetRounds(ctx, startAfter, startBefore)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetRoundsResponse{Rounds: rounds}, nil
}

func (a *adminHandler) GetScheduledSweep(ctx context.Context, _ *arkv1.GetScheduledSweepRequest) (*arkv1.GetScheduledSweepResponse, error) {
	scheduledSweeps, err := a.adminService.GetScheduledSweeps(ctx)
	if err != nil {
		return nil, err
	}

	sweeps := make([]*arkv1.ScheduledSweep, 0)

	for _, sweep := range scheduledSweeps {
		outputs := make([]*arkv1.SweepableOutput, 0)

		for _, output := range sweep.SweepableOutputs {
			outputs = append(outputs, &arkv1.SweepableOutput{
				Txid:        output.TxId,
				Vout:        output.Vout,
				ScheduledAt: output.ScheduledAt,
				Amount:      convertSatsToBTCStr(output.Amount),
			})
		}

		sweeps = append(sweeps, &arkv1.ScheduledSweep{
			RoundId: sweep.RoundId,
			Outputs: outputs,
		})
	}

	return &arkv1.GetScheduledSweepResponse{Sweeps: sweeps}, nil
}

func (a *adminHandler) CreateNote(ctx context.Context, req *arkv1.CreateNoteRequest) (*arkv1.CreateNoteResponse, error) {
	amount := req.GetAmount()
	quantity := req.GetQuantity()
	if quantity == 0 {
		quantity = 1
	}

	if amount == 0 {
		return nil, status.Error(codes.InvalidArgument, "amount must be greater than 0")
	}

	notes, err := a.adminService.CreateNotes(ctx, amount, int(quantity))
	if err != nil {
		return nil, err
	}

	if len(a.noteUriPrefix) > 0 {
		notesWithURI := make([]string, 0, len(notes))
		for _, note := range notes {
			notesWithURI = append(notesWithURI, fmt.Sprintf("%s://%s", a.noteUriPrefix, note))
		}

		return &arkv1.CreateNoteResponse{Notes: notesWithURI}, nil
	}

	return &arkv1.CreateNoteResponse{Notes: notes}, nil
}

func (a *adminHandler) GetMarketHourConfig(
	ctx context.Context,
	request *arkv1.GetMarketHourConfigRequest,
) (*arkv1.GetMarketHourConfigResponse, error) {
	config, err := a.arkService.GetMarketHourConfig(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.GetMarketHourConfigResponse{
		Config: &arkv1.MarketHourConfig{
			StartTime:     config.StartTime.Unix(),
			EndTime:       config.EndTime.Unix(),
			Period:        int64(config.Period.Seconds()),
			RoundInterval: int64(config.RoundInterval.Seconds()),
		},
	}, nil
}

func (a *adminHandler) UpdateMarketHourConfig(
	ctx context.Context,
	req *arkv1.UpdateMarketHourConfigRequest,
) (*arkv1.UpdateMarketHourConfigResponse, error) {
	if err := a.arkService.UpdateMarketHourConfig(
		ctx,
		time.Unix(req.GetConfig().GetStartTime(), 0),
		time.Unix(req.GetConfig().GetEndTime(), 0),
		time.Duration(req.GetConfig().GetPeriod())*time.Second,
		time.Duration(req.GetConfig().GetRoundInterval())*time.Second,
	); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.UpdateMarketHourConfigResponse{}, nil
}

func (a *adminHandler) ListIntents(
	ctx context.Context, req *arkv1.ListIntentsRequest,
) (*arkv1.ListIntentsResponse, error) {
	requests, err := a.arkService.GetTxRequestQueue(ctx, req.GetIntentIds()...)
	if err != nil {
		return nil, err
	}

	return &arkv1.ListIntentsResponse{Intents: intentsInfo(requests).toProto()}, nil
}

func (a *adminHandler) DeleteIntents(
	ctx context.Context, req *arkv1.DeleteIntentsRequest,
) (*arkv1.DeleteIntentsResponse, error) {
	if err := a.arkService.DeleteTxRequests(ctx, req.GetIntentIds()...); err != nil {
		return nil, err
	}

	return &arkv1.DeleteIntentsResponse{}, nil
}
