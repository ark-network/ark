package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/psetv2"
)

var (
	paymentsThreshold = int64(128)
	dustAmount        = uint64(450)
)

type Service interface {
	Start() error
	Stop()
	SpendVtxos(ctx context.Context, inputs []domain.VtxoKey) (string, error)
	ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver) error
	SignVtxos(ctx context.Context, forfeitTxs []string) error
	GetRoundByTxid(ctx context.Context, poolTxid string) (*domain.Round, error)
	GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent
	UpdatePaymentStatus(ctx context.Context, id string) error
	ListVtxos(ctx context.Context, pubkey *secp256k1.PublicKey) ([]domain.Vtxo, error)
	GetInfo(ctx context.Context) (string, int64, int64, error)
	Onboard(ctx context.Context, boardingTx string, congestionTree tree.CongestionTree, userPubkey *secp256k1.PublicKey) error
}

type service struct {
	network             common.Network
	onchainNework       network.Network
	pubkey              *secp256k1.PublicKey
	roundLifetime       int64
	roundInterval       int64
	unilateralExitDelay int64
	minRelayFee         uint64

	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder
	scanner     ports.BlockchainScanner
	sweeper     *sweeper

	paymentRequests *paymentsMap
	forfeitTxs      *forfeitTxsMap

	eventsCh chan domain.RoundEvent
}

func NewService(
	network common.Network, onchainNetwork network.Network,
	roundInterval, roundLifetime, unilateralExitDelay int64, minRelayFee uint64,
	walletSvc ports.WalletService, repoManager ports.RepoManager,
	builder ports.TxBuilder, scanner ports.BlockchainScanner,
	scheduler ports.SchedulerService,
) (Service, error) {
	eventsCh := make(chan domain.RoundEvent)
	paymentRequests := newPaymentsMap(nil)

	genesisHash, _ := chainhash.NewHashFromStr(onchainNetwork.GenesisBlockHash)
	forfeitTxs := newForfeitTxsMap(genesisHash)
	pubkey, err := walletSvc.GetPubkey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pubkey: %s", err)
	}

	sweeper := newSweeper(walletSvc, repoManager, builder, scheduler)

	svc := &service{
		network, onchainNetwork, pubkey,
		roundLifetime, roundInterval, unilateralExitDelay, minRelayFee,
		walletSvc, repoManager, builder, scanner, sweeper,
		paymentRequests, forfeitTxs, eventsCh,
	}
	repoManager.RegisterEventsHandler(
		func(round *domain.Round) {
			go svc.updateVtxoSet(round)
			go svc.propagateEvents(round)
			go svc.scheduleSweepVtxosForRound(round)
		},
	)

	if err := svc.restoreWatchingVtxos(); err != nil {
		return nil, fmt.Errorf("failed to restore watching vtxos: %s", err)
	}
	go svc.listenToRedemptions()
	return svc, nil
}

func (s *service) Start() error {
	log.Debug("starting sweeper service")
	if err := s.sweeper.start(); err != nil {
		return err
	}

	log.Debug("starting app service")
	go s.start()
	return nil
}

func (s *service) Stop() {
	s.sweeper.stop()
	// nolint
	vtxos, _ := s.repoManager.Vtxos().GetSpendableVtxos(
		context.Background(), "",
	)
	if len(vtxos) > 0 {
		s.stopWatchingVtxos(vtxos)
	}

	s.wallet.Close()
	log.Debug("closed connection to wallet")
	s.repoManager.Close()
	log.Debug("closed connection to db")
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

func (s *service) SignVtxos(ctx context.Context, forfeitTxs []string) error {
	return s.forfeitTxs.sign(forfeitTxs)
}

func (s *service) ListVtxos(ctx context.Context, pubkey *secp256k1.PublicKey) ([]domain.Vtxo, error) {
	pk := hex.EncodeToString(pubkey.SerializeCompressed())
	return s.repoManager.Vtxos().GetSpendableVtxos(ctx, pk)
}

func (s *service) GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent {
	return s.eventsCh
}

func (s *service) GetRoundByTxid(ctx context.Context, poolTxid string) (*domain.Round, error) {
	return s.repoManager.Rounds().GetRoundWithTxid(ctx, poolTxid)
}

func (s *service) GetInfo(ctx context.Context) (string, int64, int64, error) {
	pubkey := hex.EncodeToString(s.pubkey.SerializeCompressed())
	return pubkey, s.roundLifetime, s.unilateralExitDelay, nil
}

func (s *service) Onboard(
	ctx context.Context, boardingTx string,
	congestionTree tree.CongestionTree, userPubkey *secp256k1.PublicKey,
) error {
	if err := tree.ValidateCongestionTree(
		congestionTree, boardingTx, s.pubkey, s.roundLifetime,
	); err != nil {
		return err
	}
	ptx, err := psetv2.NewPsetFromBase64(boardingTx)
	if err != nil {
		return fmt.Errorf("failed to parse boarding tx: %s", err)
	}

	utx, _ := ptx.UnsignedTx()
	txid := utx.TxHash().String()

	isConfirmed, _, err := s.wallet.IsTransactionConfirmed(ctx, txid)
	if err != nil {
		return fmt.Errorf("failed to fetch confirmation info for boaridng tx: %s", err)
	}
	if !isConfirmed {
		return fmt.Errorf("boarding tx not confirmed yet, please retry later")
	}

	pubkey := hex.EncodeToString(userPubkey.SerializeCompressed())
	payments := getPaymentsFromOnboarding(congestionTree, pubkey)
	round := domain.NewFinalizedRound(
		dustAmount, pubkey, txid, boardingTx, congestionTree, payments,
	)

	return s.saveEvents(ctx, round.Id, round.Events())
}

func (s *service) start() {
	s.startRound()
}

func (s *service) startRound() {
	round := domain.NewRound(dustAmount)
	changes, _ := round.StartRegistration()
	if err := s.saveEvents(
		context.Background(), round.Id, changes,
	); err != nil {
		log.WithError(err).Warn("failed to store new round events")
		return
	}

	defer func() {
		time.Sleep(time.Duration(s.roundInterval/2) * time.Second)
		s.startFinalization()
	}()

	log.Debugf("started registration stage for new round: %s", round.Id)
}

func (s *service) startFinalization() {
	ctx := context.Background()
	round, err := s.repoManager.Rounds().GetCurrentRound(ctx)
	if err != nil {
		log.WithError(err).Warn("failed to retrieve current round")
		return
	}

	var changes []domain.RoundEvent
	defer func() {
		if err := s.saveEvents(ctx, round.Id, changes); err != nil {
			log.WithError(err).Warn("failed to store new round events")
		}

		if round.IsFailed() {
			s.startRound()
			return
		}
		time.Sleep(time.Duration((s.roundInterval/2)-1) * time.Second)
		s.finalizeRound()
	}()

	if round.IsFailed() {
		return
	}

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
	changes, err = round.RegisterPayments(payments)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to register payments: %s", err))
		log.WithError(err).Warn("failed to register payments")
		return
	}

	unsignedPoolTx, tree, err := s.builder.BuildPoolTx(s.pubkey, payments, s.minRelayFee)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to create pool tx: %s", err))
		log.WithError(err).Warn("failed to create pool tx")
		return
	}

	log.Debugf("pool tx created for round %s", round.Id)

	connectors, forfeitTxs, err := s.builder.BuildForfeitTxs(s.pubkey, unsignedPoolTx, payments)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to create connectors and forfeit txs: %s", err))
		log.WithError(err).Warn("failed to create connectors and forfeit txs")
		return
	}

	log.Debugf("forfeit transactions created for round %s", round.Id)

	events, err := round.StartFinalization(connectors, tree, unsignedPoolTx)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to start finalization: %s", err))
		log.WithError(err).Warn("failed to start finalization")
		return
	}
	changes = append(changes, events...)

	s.forfeitTxs.push(forfeitTxs)

	log.Debugf("started finalization stage for round: %s", round.Id)
}

func (s *service) finalizeRound() {
	defer s.startRound()

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
		if err := s.saveEvents(ctx, round.Id, changes); err != nil {
			log.WithError(err).Warn("failed to store new round events")
			return
		}
	}()

	forfeitTxs, leftUnsigned := s.forfeitTxs.pop()
	if len(leftUnsigned) > 0 {
		err := fmt.Errorf("%d forfeit txs left to sign", len(leftUnsigned))
		changes = round.Fail(fmt.Errorf("failed to finalize round: %s", err))
		log.WithError(err).Warn("failed to finalize round")
		return
	}

	log.Debugf("signing round transaction %s\n", round.Id)
	signedPoolTx, err := s.wallet.SignPset(ctx, round.UnsignedTx, true)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to sign round tx: %s", err))
		log.WithError(err).Warn("failed to sign round tx")
		return
	}

	txid, err := s.wallet.BroadcastTransaction(ctx, signedPoolTx)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to broadcast pool tx: %s", err))
		log.WithError(err).Warn("failed to broadcast pool tx")
		return
	}

	changes, _ = round.EndFinalization(forfeitTxs, txid)

	log.Debugf("finalized round %s with pool tx %s", round.Id, round.Txid)
}

func (s *service) listenToRedemptions() {
	ctx := context.Background()
	chVtxos := s.scanner.GetNotificationChannel(ctx)
	for vtxoKeys := range chVtxos {
		if len(vtxoKeys) > 0 {
			for {
				// TODO: make sure that the vtxos haven't been already spent, otherwise
				// broadcast the corresponding forfeit tx and connector to prevent
				// getting cheated.
				vtxos, err := s.repoManager.Vtxos().RedeemVtxos(ctx, vtxoKeys)
				if err != nil {
					log.WithError(err).Warn("failed to redeem vtxos, retrying...")
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if len(vtxos) > 0 {
					log.Debugf("redeemed %d vtxos", len(vtxos))
				}
				break
			}
		}
	}
}

func (s *service) updateVtxoSet(round *domain.Round) {
	// Update the vtxo set only after a round is finalized.
	if !round.IsEnded() {
		return
	}

	ctx := context.Background()
	repo := s.repoManager.Vtxos()
	spentVtxos := getSpentVtxos(round.Payments)
	if len(spentVtxos) > 0 {
		for {
			if err := repo.SpendVtxos(ctx, spentVtxos); err != nil {
				log.WithError(err).Warn("failed to add new vtxos, retrying soon")
				time.Sleep(100 * time.Millisecond)
				continue
			}
			log.Debugf("spent %d vtxos", len(spentVtxos))
			break
		}
	}

	newVtxos := s.getNewVtxos(round)
	for {
		if err := repo.AddVtxos(ctx, newVtxos); err != nil {
			log.WithError(err).Warn("failed to add new vtxos, retrying soon")
			time.Sleep(100 * time.Millisecond)
			continue
		}
		log.Debugf("added %d new vtxos", len(newVtxos))
		break
	}

	go func() {
		for {
			if err := s.startWatchingVtxos(newVtxos); err != nil {
				log.WithError(err).Warn(
					"failed to start watching vtxos, retrying in a moment...",
				)
				continue
			}
			log.Debugf("started watching %d vtxos", len(newVtxos))
			return
		}
	}()
}

func (s *service) propagateEvents(round *domain.Round) {
	lastEvent := round.Events()[len(round.Events())-1]
	switch e := lastEvent.(type) {
	case domain.RoundFinalizationStarted:
		forfeitTxs := s.forfeitTxs.view()
		s.eventsCh <- domain.RoundFinalizationStarted{
			Id:                 e.Id,
			CongestionTree:     e.CongestionTree,
			Connectors:         e.Connectors,
			PoolTx:             e.PoolTx,
			UnsignedForfeitTxs: forfeitTxs,
		}
	case domain.RoundFinalized, domain.RoundFailed:
		s.eventsCh <- e
	}
}

func (s *service) scheduleSweepVtxosForRound(round *domain.Round) {
	// Schedule the sweeping procedure only for completed round.
	if !round.IsEnded() {
		return
	}

	expirationTimestamp := time.Now().Add(
		time.Duration(s.roundLifetime+30) * time.Second,
	)

	if err := s.sweeper.schedule(
		expirationTimestamp.Unix(), round.Txid, round.CongestionTree,
	); err != nil {
		log.WithError(err).Warn("failed to schedule sweep tx")
	}
}

func (s *service) getNewVtxos(round *domain.Round) []domain.Vtxo {
	leaves := round.CongestionTree.Leaves()
	vtxos := make([]domain.Vtxo, 0)
	for _, node := range leaves {
		tx, _ := psetv2.NewPsetFromBase64(node.Tx)
		for i, out := range tx.Outputs {
			for _, p := range round.Payments {
				var pubkey string
				found := false
				for _, r := range p.Receivers {
					if r.IsOnchain() {
						continue
					}

					buf, _ := hex.DecodeString(r.Pubkey)
					pk, _ := secp256k1.ParsePubKey(buf)
					script, _ := s.builder.GetVtxoScript(pk, s.pubkey)
					if bytes.Equal(script, out.Script) {
						found = true
						pubkey = r.Pubkey
						break
					}
				}
				if found {
					vtxos = append(vtxos, domain.Vtxo{
						VtxoKey:  domain.VtxoKey{Txid: node.Txid, VOut: uint32(i)},
						Receiver: domain.Receiver{Pubkey: pubkey, Amount: out.Value},
						PoolTx:   round.Txid,
					})
					break
				}
			}
		}
	}
	return vtxos
}

func (s *service) startWatchingVtxos(vtxos []domain.Vtxo) error {
	scripts, err := s.extractVtxosScripts(vtxos)
	if err != nil {
		return err
	}

	return s.scanner.WatchScripts(context.Background(), scripts)
}

func (s *service) stopWatchingVtxos(vtxos []domain.Vtxo) {
	scripts, err := s.extractVtxosScripts(vtxos)
	if err != nil {
		log.WithError(err).Warn("failed to extract scripts from vtxos")
		return
	}

	for {
		if err := s.scanner.UnwatchScripts(context.Background(), scripts); err != nil {
			log.WithError(err).Warn("failed to stop watching vtxos, retrying in a moment...")
			time.Sleep(100 * time.Millisecond)
			continue
		}
		log.Debugf("stopped watching %d vtxos", len(vtxos))
		break
	}
}

func (s *service) restoreWatchingVtxos() error {
	vtxos, err := s.repoManager.Vtxos().GetSpendableVtxos(
		context.Background(), "",
	)
	if err != nil {
		return err
	}
	if len(vtxos) <= 0 {
		return nil
	}

	if err := s.startWatchingVtxos(vtxos); err != nil {
		return err
	}

	log.Debugf("restored watching %d vtxos", len(vtxos))
	return nil
}

func (s *service) extractVtxosScripts(vtxos []domain.Vtxo) ([]string, error) {
	indexedScripts := make(map[string]struct{})
	for _, vtxo := range vtxos {
		buf, err := hex.DecodeString(vtxo.Pubkey)
		if err != nil {
			return nil, err
		}
		userPubkey, err := secp256k1.ParsePubKey(buf)
		if err != nil {
			return nil, err
		}
		script, err := s.builder.GetVtxoScript(userPubkey, s.pubkey)
		if err != nil {
			return nil, err
		}

		indexedScripts[hex.EncodeToString(script)] = struct{}{}
	}
	scripts := make([]string, 0, len(indexedScripts))
	for script := range indexedScripts {
		scripts = append(scripts, script)
	}
	return scripts, nil
}

func (s *service) saveEvents(
	ctx context.Context, id string, events []domain.RoundEvent,
) error {
	if len(events) <= 0 {
		return nil
	}
	round, err := s.repoManager.Events().Save(ctx, id, events...)
	if err != nil {
		return err
	}
	return s.repoManager.Rounds().AddOrUpdateRound(ctx, *round)
}

func getSpentVtxos(payments map[string]domain.Payment) []domain.VtxoKey {
	vtxos := make([]domain.VtxoKey, 0)
	for _, p := range payments {
		for _, vtxo := range p.Inputs {
			vtxos = append(vtxos, vtxo.VtxoKey)
		}
	}
	return vtxos
}

func getPaymentsFromOnboarding(
	congestionTree tree.CongestionTree, userKey string,
) []domain.Payment {
	leaves := congestionTree.Leaves()
	receivers := make([]domain.Receiver, 0, len(leaves))
	for _, node := range leaves {
		ptx, _ := psetv2.NewPsetFromBase64(node.Tx)
		receiver := domain.Receiver{
			Pubkey: userKey,
			Amount: ptx.Outputs[0].Value,
		}
		receivers = append(receivers, receiver)
	}
	payment := domain.NewPaymentUnsafe(nil, receivers)
	return []domain.Payment{*payment}
}
