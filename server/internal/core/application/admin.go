package application

import (
	"context"

	"github.com/ark-network/ark/internal/core/ports"
)

type Balance struct {
	Locked    uint64
	Available uint64
}

type ArkProviderBalance struct {
	MainAccountBalance       Balance
	ConnectorsAccountBalance Balance
}

type SweepableOutput struct {
	TxId        string
	Vout        uint32
	Amount      uint64
	ScheduledAt int64
}

type ScheduledSweep struct {
	RoundId          string
	SweepableOutputs []SweepableOutput
}

type RoundDetails struct {
	RoundId          string
	TxId             string
	ForfeitedAmount  uint64
	TotalVtxosAmount uint64
	TotalExitAmount  uint64
	FeesAmount       uint64
	InputsVtxos      []string
	OutputsVtxos     []string
	ExitAddresses    []string
}

type AdminService interface {
	GetBalance(ctx context.Context) (*ArkProviderBalance, error)
	GetScheduledSweeps(ctx context.Context) ([]ScheduledSweep, error)
	GetRoundDetails(ctx context.Context, roundId string) (*RoundDetails, error)
	GetRounds(ctx context.Context, after int64, before int64) ([]string, error)
}

type adminService struct {
	walletSvc   ports.WalletService
	repoManager ports.RepoManager
	txBuilder   ports.TxBuilder
}

func NewAdminService(walletSvc ports.WalletService, repoManager ports.RepoManager, txBuilder ports.TxBuilder) AdminService {
	return &adminService{
		walletSvc:   walletSvc,
		repoManager: repoManager,
		txBuilder:   txBuilder,
	}
}

func (a *adminService) GetBalance(ctx context.Context) (*ArkProviderBalance, error) {
	mainBalance, mainBalanceLocked, err := a.walletSvc.MainAccountBalance(ctx)
	if err != nil {
		return nil, err
	}

	connectorBalance, connectorBalanceLocked, err := a.walletSvc.ConnectorsAccountBalance(ctx)
	if err != nil {
		return nil, err
	}

	return &ArkProviderBalance{
		MainAccountBalance:       Balance{Locked: mainBalanceLocked, Available: mainBalance},
		ConnectorsAccountBalance: Balance{Locked: connectorBalanceLocked, Available: connectorBalance},
	}, nil
}

func (a *adminService) GetRoundDetails(ctx context.Context, roundId string) (*RoundDetails, error) {
	round, err := a.repoManager.Rounds().GetRoundWithId(ctx, roundId)
	if err != nil {
		return nil, err
	}

	roundDetails := &RoundDetails{
		RoundId:          round.Id,
		TxId:             round.Txid,
		ForfeitedAmount:  0,
		TotalVtxosAmount: 0,
		TotalExitAmount:  0,
		ExitAddresses:    []string{},
		FeesAmount:       0,
		InputsVtxos:      []string{},
		OutputsVtxos:     []string{},
	}

	for _, payment := range round.Payments {
		// TODO: Add fees amount
		roundDetails.ForfeitedAmount += payment.TotalInputAmount()

		for _, receiver := range payment.Receivers {
			if receiver.IsOnchain() {
				roundDetails.TotalExitAmount += receiver.Amount
				roundDetails.ExitAddresses = append(roundDetails.ExitAddresses, receiver.OnchainAddress)
				continue
			}

			roundDetails.TotalVtxosAmount += receiver.Amount
		}

		for _, input := range payment.Inputs {
			roundDetails.InputsVtxos = append(roundDetails.InputsVtxos, input.Txid)
		}
	}

	vtxos, err := a.repoManager.Vtxos().GetVtxosForRound(ctx, round.Txid)
	if err != nil {
		return nil, err
	}

	for _, vtxo := range vtxos {
		roundDetails.OutputsVtxos = append(roundDetails.OutputsVtxos, vtxo.Txid)
	}

	return roundDetails, nil
}

func (a *adminService) GetRounds(ctx context.Context, after int64, before int64) ([]string, error) {
	return a.repoManager.Rounds().GetRoundsIds(ctx, after, before)
}

func (a *adminService) GetScheduledSweeps(ctx context.Context) ([]ScheduledSweep, error) {
	sweepableRounds, err := a.repoManager.Rounds().GetSweepableRounds(ctx)
	if err != nil {
		return nil, err
	}

	scheduledSweeps := make([]ScheduledSweep, 0, len(sweepableRounds))

	for _, round := range sweepableRounds {
		sweepable, err := findSweepableOutputs(
			ctx, a.walletSvc, a.txBuilder, round.CongestionTree,
		)
		if err != nil {
			return nil, err
		}

		sweepableOutputs := make([]SweepableOutput, 0)
		for expirationTime, inputs := range sweepable {
			for _, input := range inputs {
				sweepableOutputs = append(sweepableOutputs, SweepableOutput{
					TxId:        input.GetHash().String(),
					Vout:        input.GetIndex(),
					Amount:      input.GetAmount(),
					ScheduledAt: expirationTime,
				})
			}
		}

		scheduledSweeps = append(scheduledSweeps, ScheduledSweep{
			RoundId:          round.Id,
			SweepableOutputs: sweepableOutputs,
		})
	}

	return scheduledSweeps, nil
}
