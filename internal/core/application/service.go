package application

import (
	"context"
	"fmt"

	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/address"
)

type service struct {
	roundInterval int64

	wallet      ports.WalletService
	scheduler   ports.SchedulerService
	repoManager ports.RepoManager
}

func NewService(
	interval int64,
	walletSvc ports.WalletService, schedulerSvc ports.SchedulerService, repoManager ports.RepoManager,
) *service {
	return &service{interval, walletSvc, schedulerSvc, repoManager}
}

func (s *service) Start() {
	s.start()
}

func (s *service) start() {
	startImmediately := true
	finalizationInterval := int64(s.roundInterval / 2)
	s.scheduler.ScheduleTask(s.roundInterval, startImmediately, s.startRoundAndRegistration)
	s.scheduler.ScheduleTask(finalizationInterval, !startImmediately, s.startFinalization)
	s.scheduler.ScheduleTask(s.roundInterval-1, !startImmediately, s.endRoundAndFinalization)
}

func (s *service) startRoundAndRegistration() {
	round := domain.NewRound()
	changes, _ := round.StartRegistration()
	if err := s.repoManager.Events().Save(context.Background(), changes...); err != nil {
		log.WithError(err).Warn("failed to store new round events")
		return
	}

	log.Debugf("started registration stage for new round: %s", round.Id)
}

func (s *service) startFinalization() {
	ctx := context.Background()
	round, err := s.repoManager.Rounds().GetCurrentRound(ctx)
	if err != nil {
		log.WithError(err).Warn("failed to retrieve current round")
		return
	}
	if round.IsFailed() {
		return
	}

	// TODO: create forfeit txs and congestion tree from registered payments
	events, _ := round.EndRegistration(nil, nil)
	changes := append([]domain.RoundEvent{}, events...)
	events, _ = round.StartFinalization()
	changes = append(changes, events...)

	if err := s.repoManager.Events().Save(ctx, changes...); err != nil {
		log.WithError(err).Warn("failed to store new round events")
		return
	}

	log.Debugf("ended registration stage for round: %s", round.Id)
	log.Debugf("started finalization stage for round: %s", round.Id)
}

func (s *service) endRoundAndFinalization() {
	ctx := context.Background()
	round, err := s.repoManager.Rounds().GetCurrentRound(ctx)
	if err != nil {
		log.WithError(err).Warn("failed to retrieve current round")
		return
	}
	if round.IsFailed() {
		return
	}

	addresses, err := s.wallet.Account().DeriveAddresses(ctx, 2)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create pool tx: %s", err))
		log.WithError(err).Warn("failed to create pool tx")
		return
	}

	sharedOutScript, _ := address.ToOutputScript(addresses[0])
	connectorOutScript, _ := address.ToOutputScript(addresses[1])
	outs := []ports.TxOutput{
		output{
			script: sharedOutScript,
			amount: round.TotOutputAmount(),
		},
		output{
			script: connectorOutScript,
			amount: round.TotInputAmount(),
		},
	}
	txhex, err := s.wallet.Transaction().Transfer(ctx, outs)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create pool tx: %s", err))
		log.WithError(err).Warn("failed to create pool tx")
		return
	}

	txid, err := s.wallet.Transaction().BroadcastTransaction(ctx, txhex)
	if err != nil {
		round.Fail(fmt.Errorf("failed to broadcast pool tx: %s", err))
		log.WithError(err).Warn("failed to broadcast pool tx")
		return
	}

	round.EndFinalization(txid)
	if err := s.repoManager.Events().Save(ctx, round.Changes...); err != nil {
		log.WithError(err).Warn("failed to store new round events")
		return
	}

	log.Debugf("ended round %s with pool tx %s", round.Id, round.Txid)
}
