package handlers

import (
	"context"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/server/internal/core/application"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type adminHandler struct {
	adminService application.AdminService
	aspService   application.Service
}

func NewAdminHandler(
	adminService application.AdminService, aspService application.Service,
) arkv1.AdminServiceServer {
	return &adminHandler{adminService, aspService}
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
		Txid:             details.TxId,
		ForfeitedAmount:  convertSatoshis(details.ForfeitedAmount),
		TotalVtxosAmount: convertSatoshis(details.TotalVtxosAmount),
		TotalExitAmount:  convertSatoshis(details.TotalExitAmount),
		FeesAmount:       convertSatoshis(details.FeesAmount),
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
				Amount:      convertSatoshis(output.Amount),
			})
		}

		sweeps = append(sweeps, &arkv1.ScheduledSweep{
			RoundId: sweep.RoundId,
			Outputs: outputs,
		})
	}

	return &arkv1.GetScheduledSweepResponse{Sweeps: sweeps}, nil
}

func (a *adminHandler) CreateVoucher(ctx context.Context, req *arkv1.CreateVoucherRequest) (*arkv1.CreateVoucherResponse, error) {
	amount := req.GetAmount()
	quantity := req.GetQuantity()
	if quantity == 0 {
		quantity = 1
	}

	if amount == 0 {
		return nil, status.Error(codes.InvalidArgument, "amount must be greater than 0")
	}

	vouchers, err := a.adminService.CreateVouchers(ctx, amount, int(quantity))
	if err != nil {
		return nil, err
	}

	return &arkv1.CreateVoucherResponse{Vouchers: vouchers}, nil
}

// convert sats to string BTC
func convertSatoshis(sats uint64) string {
	btc := float64(sats) * 1e-8
	return fmt.Sprintf("%.8f", btc)
}
