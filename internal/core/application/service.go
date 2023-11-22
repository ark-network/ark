package application

import (
	"context"
	"fmt"

	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	log "github.com/sirupsen/logrus"
)

type service struct {
	roundInterval int64

	wallet      ports.WalletService
	scheduler   ports.SchedulerService
	repoManager ports.RepoManager
	builder     ports.TxBuilder
}

func NewService(
	interval int64,
	walletSvc ports.WalletService, schedulerSvc ports.SchedulerService,
	repoManager ports.RepoManager, builder ports.TxBuilder,
) *service {
	return &service{interval, walletSvc, schedulerSvc, repoManager, builder}
}

func (s *service) Start() {
	s.start()
}

func (s *service) start() {
	startImmediately := true
	finalizationInterval := int64(s.roundInterval / 2)
	s.scheduler.ScheduleTask(s.roundInterval, startImmediately, s.startRound)
	s.scheduler.ScheduleTask(finalizationInterval, !startImmediately, s.startFinalization)
	s.scheduler.ScheduleTask(s.roundInterval-1, !startImmediately, s.finalizeRound)
}

func (s *service) startRound() {
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

	allPayments := make([]domain.Payment, 0, len(round.Payments))
	for _, p := range round.Payments {
		allPayments = append(allPayments, p)
	}

	signedPoolTx, err := s.builder.BuildPoolTx(s.wallet, allPayments)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create pool tx: %s", err))
		log.WithError(err).Warn("failed to create pool tx")
		return
	}

	tree, err := s.builder.BuildCongestionTree(signedPoolTx, allPayments)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create congestion tree: %s", err))
		log.WithError(err).Warn("failed to create congestion tree")
		return
	}

	connectors, forfeitTxs, err := s.builder.BuildForfeitTxs(signedPoolTx, allPayments)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create connectors and forfeit txs: %s", err))
		log.WithError(err).Warn("failed to create connectors and forfeit txs")
		return
	}

	changes, _ := round.StartFinalization(connectors, forfeitTxs, tree, signedPoolTx)

	if err := s.repoManager.Events().Save(ctx, changes...); err != nil {
		log.WithError(err).Warn("failed to store new round events")
		return
	}

	log.Debugf("started finalization stage for round: %s", round.Id)
}

func (s *service) finalizeRound() {
	ctx := context.Background()
	round, err := s.repoManager.Rounds().GetCurrentRound(ctx)
	if err != nil {
		log.WithError(err).Warn("failed to retrieve current round")
		return
	}
	if round.IsFailed() {
		return
	}

	txid, err := s.wallet.Transaction().BroadcastTransaction(ctx, round.TxHex)
	if err != nil {
		round.Fail(fmt.Errorf("failed to broadcast pool tx: %s", err))
		log.WithError(err).Warn("failed to broadcast pool tx")
		return
	}

	changes, _ := round.EndFinalization(txid)
	if err := s.repoManager.Events().Save(ctx, changes...); err != nil {
		log.WithError(err).Warn("failed to store new round events")
		return
	}

	log.Debugf("finalized round %s with pool tx %s", round.Id, round.Txid)
}
