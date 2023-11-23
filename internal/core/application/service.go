package application

import (
	"context"
	"fmt"

	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	log "github.com/sirupsen/logrus"
)

const paymentsThreshold = 128

type service struct {
	roundInterval int64

	wallet          ports.WalletService
	scheduler       ports.SchedulerService
	repoManager     ports.RepoManager
	builder         ports.TxBuilder
	paymentRequests *paymentsMap
	forfeitTxs      *forfeitTxsMap
}

func NewService(
	interval int64,
	walletSvc ports.WalletService, schedulerSvc ports.SchedulerService,
	repoManager ports.RepoManager, builder ports.TxBuilder,
) *service {
	paymentRequests := newPaymentsMap(nil)
	forfeitTxs := newForfeitTxsMap()
	return &service{
		interval, walletSvc, schedulerSvc, repoManager, builder,
		paymentRequests, forfeitTxs,
	}
}

func (s *service) Start() error {
	return s.start()
}

func (s *service) SpendVtxos(ctx context.Context, inputs []domain.VtxoKey) (string, error) {
	vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, inputs)
	if err != nil {
		return "", err
	}
	for _, v := range vtxos {
		if v.Spent {
			return "", fmt.Errorf("input %s:%d already spent", v.Txid, v.VOut)
		}
	}

	payment := domain.NewPayment(vtxos)
	if err := s.paymentRequests.push(payment); err != nil {
		return "", err
	}
	return payment.Id, nil
}

func (s *service) ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver) error {
	// Check credentials
	payment, ok := s.paymentRequests.view(creds)
	if !ok {
		return fmt.Errorf("invalid credentials")
	}

	// Check that input and output and output amounts match.
	ins := make([]domain.VtxoKey, 0, len(payment.Inputs))
	for _, in := range payment.Inputs {
		ins = append(ins, in.VtxoKey)
	}
	vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, ins)
	if err != nil {
		return err
	}
	inAmount := uint64(0)
	for _, v := range vtxos {
		inAmount += v.Amount
	}
	outAmount := uint64(0)
	for _, v := range receivers {
		outAmount += v.Amount
	}
	if inAmount != outAmount {
		return fmt.Errorf("input and output amounts mismatch")
	}

	payment.Receivers = receivers
	return s.paymentRequests.update(*payment)
}

func (s *service) SignVtxos(ctx context.Context, forfeitTxs map[string]string) error {
	for txid, tx := range forfeitTxs {
		if err := s.forfeitTxs.sign(txid, tx); err != nil {
			return fmt.Errorf("invalid forfeit tx %s: %s", txid, err)
		}
	}
	return nil
}

func (s *service) start() error {
	startImmediately := true
	finalizationInterval := int64(s.roundInterval / 2)
	if err := s.scheduler.ScheduleTask(
		s.roundInterval, startImmediately, s.startRound,
	); err != nil {
		return err
	}
	if err := s.scheduler.ScheduleTask(
		finalizationInterval, !startImmediately, s.startFinalization,
	); err != nil {
		return err
	}
	return s.scheduler.ScheduleTask(
		s.roundInterval-1, !startImmediately, s.finalizeRound,
	)
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

	// TODO: understand how many payments must be popped from the queue and actually registered for the round
	num := s.paymentRequests.len()
	if num > paymentsThreshold {
		num = paymentsThreshold
	}
	payments := s.paymentRequests.pop(num)
	changes, _ := round.RegisterPayments(payments)

	signedPoolTx, err := s.builder.BuildPoolTx(s.wallet, payments)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create pool tx: %s", err))
		log.WithError(err).Warn("failed to create pool tx")
		return
	}

	tree, err := s.builder.BuildCongestionTree(signedPoolTx, payments)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create congestion tree: %s", err))
		log.WithError(err).Warn("failed to create congestion tree")
		return
	}

	connectors, forfeitTxs, err := s.builder.BuildForfeitTxs(signedPoolTx, payments)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create connectors and forfeit txs: %s", err))
		log.WithError(err).Warn("failed to create connectors and forfeit txs")
		return
	}

	events, _ := round.StartFinalization(connectors, tree, signedPoolTx)
	changes = append(changes, events...)

	if err := s.repoManager.Events().Save(ctx, changes...); err != nil {
		log.WithError(err).Warn("failed to store new round events")
		return
	}

	s.forfeitTxs.push(forfeitTxs)

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

	forfeitTxs, leftUnsigned := s.forfeitTxs.pop()
	if len(leftUnsigned) > 0 {
		err := fmt.Errorf("%d forfeit txs left to sign", len(leftUnsigned))
		round.Fail(fmt.Errorf("failed to finalize round: %s", err))
		log.WithError(err).Warn("failed to finalize round")
		return
	}

	txid, err := s.wallet.Transaction().BroadcastTransaction(ctx, round.TxHex)
	if err != nil {
		round.Fail(fmt.Errorf("failed to broadcast pool tx: %s", err))
		log.WithError(err).Warn("failed to broadcast pool tx")
		return
	}

	changes, _ := round.EndFinalization(forfeitTxs, txid)
	if err := s.repoManager.Events().Save(ctx, changes...); err != nil {
		log.WithError(err).Warn("failed to store new round events")
		return
	}

	log.Debugf("finalized round %s with pool tx %s", round.Id, round.Txid)
}
