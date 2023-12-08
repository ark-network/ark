package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
)

var (
	paymentsThreshold = int64(128)
	dustAmount        = uint64(450)
	faucetVtxo        = domain.VtxoKey{
		Txid: "0000000000000000000000000000000000000000000000000000000000000000",
		VOut: 0,
	}
)

type Service interface {
	SpendVtxos(ctx context.Context, inputs []domain.VtxoKey) (string, error)
	ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver) error
	SignVtxos(ctx context.Context, forfeitTxs []string) error
	FaucetVtxos(ctx context.Context, pubkey string) error
	GetRoundByTxid(ctx context.Context, poolTxid string) (*domain.Round, error)
	GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent
	UpdatePaymentStatus(ctx context.Context, id string) error
	ListVtxos(ctx context.Context, pubkey string) ([]domain.Vtxo, error)
	GetPubkey(ctx context.Context) (string, error)
}

type service struct {
	roundInterval int64
	network       common.Network
	onchainNework network.Network
	pubkey        string

	wallet          ports.WalletService
	scheduler       ports.SchedulerService
	repoManager     ports.RepoManager
	builder         ports.TxBuilder
	paymentRequests *paymentsMap
	forfeitTxs      *forfeitTxsMap

	eventsCh chan domain.RoundEvent
}

func NewService(
	interval int64, network common.Network, onchainNetwork network.Network,
	walletSvc ports.WalletService, schedulerSvc ports.SchedulerService,
	repoManager ports.RepoManager, builder ports.TxBuilder,
) Service {
	pubkey := ""
	eventsCh := make(chan domain.RoundEvent)
	paymentRequests := newPaymentsMap(nil)
	forfeitTxs := newForfeitTxsMap()
	svc := &service{
		interval, network, onchainNetwork, pubkey,
		walletSvc, schedulerSvc, repoManager, builder, paymentRequests, forfeitTxs,
		eventsCh,
	}
	repoManager.RegisterEventsHandler(
		func(round *domain.Round) {
			svc.updateProjectionStore(round)
			svc.propagateEvents(round)
		},
	)
	return svc
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

	payment, err := domain.NewPayment(vtxos)
	if err != nil {
		return "", err
	}
	if err := s.paymentRequests.push(*payment); err != nil {
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

	if err := payment.AddReceivers(receivers); err != nil {
		return err
	}
	return s.paymentRequests.update(*payment)
}

func (s *service) UpdatePaymentStatus(_ context.Context, id string) error {
	return s.paymentRequests.updatePingTimestamp(id)
}

func (s *service) FaucetVtxos(ctx context.Context, pubkey string) error {
	payment, err := domain.NewPayment([]domain.Vtxo{
		{
			VtxoKey: faucetVtxo,
			Receiver: domain.Receiver{
				Pubkey: pubkey,
				Amount: 100000,
			},
		},
	})
	if err != nil {
		return err
	}

	if err := payment.AddReceivers([]domain.Receiver{
		{Pubkey: pubkey, Amount: 10000},
		{Pubkey: pubkey, Amount: 10000},
		{Pubkey: pubkey, Amount: 10000},
		{Pubkey: pubkey, Amount: 10000},
		{Pubkey: pubkey, Amount: 10000},
		{Pubkey: pubkey, Amount: 10000},
		{Pubkey: pubkey, Amount: 10000},
		{Pubkey: pubkey, Amount: 10000},
		{Pubkey: pubkey, Amount: 10000},
		{Pubkey: pubkey, Amount: 10000},
	}); err != nil {
		return err
	}

	if err := s.paymentRequests.push(*payment); err != nil {
		return err
	}
	return s.paymentRequests.updatePingTimestamp(payment.Id)
}

func (s *service) SignVtxos(ctx context.Context, forfeitTxs []string) error {
	if err := s.forfeitTxs.sign(forfeitTxs); err != nil {
		return fmt.Errorf("invalid forfeit tx: %s", err)
	}
	return nil
}

func (s *service) ListVtxos(ctx context.Context, pubkey string) ([]domain.Vtxo, error) {
	return s.repoManager.Vtxos().GetSpendableVtxosWithPubkey(ctx, pubkey)
}

func (s *service) GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent {
	return s.eventsCh
}

func (s *service) GetRoundByTxid(ctx context.Context, poolTxid string) (*domain.Round, error) {
	return s.repoManager.Rounds().GetRoundWithTxid(ctx, poolTxid)
}

func (s *service) GetPubkey(ctx context.Context) (string, error) {
	if s.pubkey == "" {
		pubkey, err := s.wallet.GetPubkey(ctx)
		if err != nil {
			return "", err
		}
		serializedPubkey, err := common.EncodePubKey(s.network.PubKey, pubkey)
		if err != nil {
			return "", err
		}
		s.pubkey = serializedPubkey
	}
	return s.pubkey, nil
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
	round := domain.NewRound(dustAmount)
	changes, _ := round.StartRegistration()
	if err := s.repoManager.Events().Save(
		context.Background(), round.Id, changes...,
	); err != nil {
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

	var changes []domain.RoundEvent
	defer func() {
		if err := s.repoManager.Events().Save(ctx, round.Id, changes...); err != nil {
			log.WithError(err).Warn("failed to store new round events")
			return
		}
	}()

	// TODO: understand how many payments must be popped from the queue and actually registered for the round
	num := s.paymentRequests.len()
	if num == 0 {
		err := fmt.Errorf("no payments registered")
		changes = round.Fail(fmt.Errorf("round aborted: %s", err))
		log.WithError(err).Debugf("round %s aborted", round.Id)
		return
	}
	if num > paymentsThreshold {
		num = paymentsThreshold
	}
	payments := s.paymentRequests.pop(num)
	changes, _ = round.RegisterPayments(payments)

	signedPoolTx, err := s.builder.BuildPoolTx(s.wallet, payments)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to create pool tx: %s", err))
		log.WithError(err).Warn("failed to create pool tx")
		return
	}

	tree, err := s.builder.BuildCongestionTree(signedPoolTx, payments)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to create congestion tree: %s", err))
		log.WithError(err).Warn("failed to create congestion tree")
		return
	}

	connectors, forfeitTxs, err := s.builder.BuildForfeitTxs(signedPoolTx, payments)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to create connectors and forfeit txs: %s", err))
		log.WithError(err).Warn("failed to create connectors and forfeit txs")
		return
	}

	events, _ := round.StartFinalization(connectors, tree, signedPoolTx)
	changes = append(changes, events...)

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

	txid, err := s.wallet.BroadcastTransaction(ctx, round.TxHex)
	if err != nil {
		round.Fail(fmt.Errorf("failed to broadcast pool tx: %s", err))
		log.WithError(err).Warn("failed to broadcast pool tx")
		return
	}

	changes, _ := round.EndFinalization(forfeitTxs, txid)
	if err := s.repoManager.Events().Save(ctx, round.Id, changes...); err != nil {
		log.WithError(err).Warn("failed to store new round events")
		return
	}

	log.Debugf("finalized round %s with pool tx %s", round.Id, round.Txid)
}

func (s *service) updateProjectionStore(round *domain.Round) {
	ctx := context.Background()
	lastChange := round.Events()[len(round.Events())-1]
	// Update the vtxo set only after a round is finalized.
	if _, ok := lastChange.(domain.RoundFinalized); ok {
		repo := s.repoManager.Vtxos()
		spentVtxos := getSpentVtxos(round.Payments)
		if len(spentVtxos) > 0 {
			for {
				if err := repo.SpendVtxos(ctx, spentVtxos); err != nil {
					log.WithError(err).Warn("failed to add new vtxos, retrying soon")
					time.Sleep(100 * time.Millisecond)
					continue
				}
				break
			}
		}

		newVtxos := getNewVtxos(s.onchainNework, round)
		for {
			if err := repo.AddVtxos(ctx, newVtxos); err != nil {
				log.WithError(err).Warn("failed to add new vtxos, retrying soon")
				time.Sleep(100 * time.Millisecond)
				continue
			}
			break
		}
	}

	// Always update the status of the round.
	for {
		if err := s.repoManager.Rounds().AddOrUpdateRound(ctx, *round); err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		break
	}
}

func (s *service) propagateEvents(round *domain.Round) {
	lastEvent := round.Events()[len(round.Events())-1]
	switch e := lastEvent.(type) {
	case domain.RoundFinalizationStarted, domain.RoundFinalized:
		s.eventsCh <- e
	}
}

func getNewVtxos(net network.Network, round *domain.Round) []domain.Vtxo {
	leaves := round.CongestionTree.Leaves()
	vtxos := make([]domain.Vtxo, 0)
	for _, node := range leaves {
		tx, _ := psetv2.NewPsetFromBase64(node.Tx)
		utx, _ := tx.UnsignedTx()
		txid := utx.TxHash().String()
		for i, out := range tx.Outputs {
			for _, p := range round.Payments {
				var pubkey string
				found := false
				for _, r := range p.Receivers {
					buf, _ := hex.DecodeString(r.Pubkey)
					pk, _ := btcec.ParsePubKey(buf)
					p2wpkh := payment.FromPublicKey(pk, &net, nil)
					addr, _ := p2wpkh.WitnessPubKeyHash()
					script, _ := address.ToOutputScript(addr)
					if bytes.Equal(script, out.Script) {
						found = true
						pubkey = hex.EncodeToString(pk.SerializeCompressed())
						break
					}
				}
				if found {
					vtxos = append(vtxos, domain.Vtxo{
						VtxoKey:  domain.VtxoKey{Txid: txid, VOut: uint32(i)},
						Receiver: domain.Receiver{Pubkey: pubkey, Amount: out.Value},
					})
					break
				}
			}
		}
	}
	return vtxos
}

func getSpentVtxos(payments map[string]domain.Payment) []domain.VtxoKey {
	vtxos := make([]domain.VtxoKey, 0)
	for _, p := range payments {
		for _, vtxo := range p.Inputs {
			if vtxo.VtxoKey == faucetVtxo {
				continue
			}
			vtxos = append(vtxos, vtxo.VtxoKey)
		}
	}
	return vtxos
}
