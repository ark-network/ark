package handlers

import (
	"context"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/internal/core/application"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type adminHandler struct {
	adminService application.AdminService
}

func NewAdminHandler(adminService application.AdminService) arkv1.AdminServiceServer {
	return &adminHandler{adminService}
}

func (a *adminHandler) GetBalance(ctx context.Context, _ *arkv1.GetBalanceRequest) (*arkv1.GetBalanceResponse, error) {
	balance, err := a.adminService.GetBalance(ctx)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetBalanceResponse{
		MainAccount: &arkv1.Balance{
			Locked:    convertSatoshis(balance.MainAccountBalance.Locked),
			Available: convertSatoshis(balance.MainAccountBalance.Available),
		},
		ConnectorsAccount: &arkv1.Balance{
			Locked:    convertSatoshis(balance.ConnectorsAccountBalance.Locked),
			Available: convertSatoshis(balance.ConnectorsAccountBalance.Available),
		},
	}, nil
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

// GetRounds implements arkv1.AdminServiceServer.
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

func (a *adminHandler) GetWalletAddress(ctx context.Context, _ *arkv1.GetWalletAddressRequest) (*arkv1.GetWalletAddressResponse, error) {
	addr, err := a.adminService.GetWalletAddress(ctx)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetWalletAddressResponse{Address: addr}, nil
}

func (a *adminHandler) GetWalletStatus(ctx context.Context, _ *arkv1.GetWalletStatusRequest) (*arkv1.GetWalletStatusResponse, error) {
	status, err := a.adminService.GetWalletStatus(ctx)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetWalletStatusResponse{
		Initialized: status.IsInitialized,
		Unlocked:    status.IsUnlocked,
		Synced:      status.IsSynced,
	}, nil
}

// convert sats to string BTC
func convertSatoshis(sats uint64) string {
	btc := float64(sats) * 1e-8
	return fmt.Sprintf("%.8f", btc)
}
