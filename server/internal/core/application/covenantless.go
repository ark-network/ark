package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	covenantlessevent "github.com/ark-network/ark/server/internal/core/application/covenantless-event"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
)

type covenantlessService struct {
	network             common.Network
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

	eventsCh     chan interface{}
	onboardingCh chan onboarding

	currentRound *domain.Round

	asyncPaymentsCache map[domain.VtxoKey]struct {
		receivers []domain.Receiver
		expireAt  int64
	}

	treeSigningSessions map[string]*musigSigningSession
}

func NewCovenantlessService(
	network common.Network,
	roundInterval, roundLifetime, unilateralExitDelay int64, minRelayFee uint64,
	walletSvc ports.WalletService, repoManager ports.RepoManager,
	builder ports.TxBuilder, scanner ports.BlockchainScanner,
	scheduler ports.SchedulerService,
) (Service, error) {
	eventsCh := make(chan interface{})
	onboardingCh := make(chan onboarding)
	paymentRequests := newPaymentsMap(nil)

	forfeitTxs := newForfeitTxsMap(builder)
	pubkey, err := walletSvc.GetPubkey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pubkey: %s", err)
	}

	sweeper := newSweeper(walletSvc, repoManager, builder, scheduler)
	asyncPaymentsCache := make(map[domain.VtxoKey]struct {
		receivers []domain.Receiver
		expireAt  int64
	})

	svc := &covenantlessService{
		network:             network,
		pubkey:              pubkey,
		roundLifetime:       roundLifetime,
		roundInterval:       roundInterval,
		unilateralExitDelay: unilateralExitDelay,
		minRelayFee:         minRelayFee,
		wallet:              walletSvc,
		repoManager:         repoManager,
		builder:             builder,
		scanner:             scanner,
		sweeper:             sweeper,
		paymentRequests:     paymentRequests,
		forfeitTxs:          forfeitTxs,
		eventsCh:            eventsCh,
		onboardingCh:        onboardingCh,
		asyncPaymentsCache:  asyncPaymentsCache,
	}

	repoManager.RegisterEventsHandler(
		func(round *domain.Round) {
			go svc.propagateEvents(round)
			go func() {
				// utxo db must be updated before scheduling the sweep events
				svc.updateVtxoSet(round)
				svc.scheduleSweepVtxosForRound(round)
			}()
		},
	)

	if err := svc.restoreWatchingVtxos(); err != nil {
		return nil, fmt.Errorf("failed to restore watching vtxos: %s", err)
	}
	go svc.listenToScannerNotifications()
	go svc.listenToOnboarding()
	return svc, nil
}

func (s *covenantlessService) Start() error {
	log.Debug("starting sweeper service")
	if err := s.sweeper.start(); err != nil {
		return err
	}

	log.Debug("starting app service")
	go s.start()
	return nil
}

func (s *covenantlessService) Stop() {
	s.sweeper.stop()
	// nolint
	vtxos, _ := s.repoManager.Vtxos().GetAllSweepableVtxos(context.Background())
	if len(vtxos) > 0 {
		s.stopWatchingVtxos(vtxos)
	}

	s.wallet.Close()
	log.Debug("closed connection to wallet")
	s.repoManager.Close()
	log.Debug("closed connection to db")
	close(s.eventsCh)
	close(s.onboardingCh)
}

func (s *covenantlessService) CompleteAsyncPayment(
	ctx context.Context, redeemTx string, unconditionalForfeitTxs []string,
) error {
	// TODO check that the user signed both transactions

	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(redeemTx), true)
	if err != nil {
		return fmt.Errorf("failed to parse redeem tx: %s", err)
	}
	redeemTxid := redeemPtx.UnsignedTx.TxID()

	spentVtxos := make([]domain.VtxoKey, 0, len(unconditionalForfeitTxs))
	for _, in := range redeemPtx.UnsignedTx.TxIn {
		spentVtxos = append(spentVtxos, domain.VtxoKey{
			Txid: in.PreviousOutPoint.Hash.String(),
			VOut: in.PreviousOutPoint.Index,
		})
	}

	asyncPayData, ok := s.asyncPaymentsCache[spentVtxos[0]]
	if !ok {
		return fmt.Errorf("async payment not found")
	}

	vtxos := make([]domain.Vtxo, 0, len(asyncPayData.receivers))
	for i, receiver := range asyncPayData.receivers {
		vtxos = append(vtxos, domain.Vtxo{
			VtxoKey: domain.VtxoKey{
				Txid: redeemTxid,
				VOut: uint32(i),
			},
			Receiver: receiver,
			ExpireAt: asyncPayData.expireAt,
			AsyncPayment: &domain.AsyncPaymentTxs{
				RedeemTx:                redeemTx,
				UnconditionalForfeitTxs: unconditionalForfeitTxs,
			},
		})
	}

	if err := s.repoManager.Vtxos().AddVtxos(ctx, vtxos); err != nil {
		return fmt.Errorf("failed to add vtxos: %s", err)
	}
	log.Infof("added %d vtxos", len(vtxos))

	if err := s.repoManager.Vtxos().SpendVtxos(ctx, spentVtxos, redeemTxid); err != nil {
		return fmt.Errorf("failed to spend vtxo: %s", err)
	}
	log.Infof("spent %d vtxos", len(spentVtxos))

	delete(s.asyncPaymentsCache, spentVtxos[0])

	return nil
}

func (s *covenantlessService) CreateAsyncPayment(
	ctx context.Context, inputs []domain.VtxoKey, receivers []domain.Receiver,
) (string, []string, error) {
	vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, inputs)
	if err != nil {
		return "", nil, err
	}
	if len(vtxos) <= 0 {
		return "", nil, fmt.Errorf("vtxos not found")
	}

	expiration := vtxos[0].ExpireAt
	for _, vtxo := range vtxos {
		if vtxo.Spent {
			return "", nil, fmt.Errorf("all vtxos must be unspent")
		}

		if vtxo.Redeemed {
			return "", nil, fmt.Errorf("all vtxos must be redeemed")
		}

		if vtxo.Swept {
			return "", nil, fmt.Errorf("all vtxos must be swept")
		}
		if vtxo.ExpireAt < expiration {
			expiration = vtxo.ExpireAt
		}
	}

	res, err := s.builder.BuildAsyncPaymentTransactions(
		vtxos, s.pubkey, receivers, s.minRelayFee,
	)
	if err != nil {
		return "", nil, fmt.Errorf("failed to build async payment txs: %s", err)
	}

	s.asyncPaymentsCache[inputs[0]] = struct {
		receivers []domain.Receiver
		expireAt  int64
	}{
		receivers: receivers,
		expireAt:  expiration,
	}

	return res.RedeemTx, res.UnconditionalForfeitTxs, nil
}

func (s *covenantlessService) SpendVtxos(ctx context.Context, inputs []domain.VtxoKey) (string, error) {
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

func (s *covenantlessService) ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver) error {
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

func (s *covenantlessService) UpdatePaymentStatus(_ context.Context, id string) ([]string, *domain.Round, error) {
	err := s.paymentRequests.updatePingTimestamp(id)
	if err != nil {
		if _, ok := err.(errPaymentNotFound); ok {
			return s.forfeitTxs.view(), s.currentRound, nil
		}

		return nil, nil, err
	}

	return nil, nil, nil
}

func (s *covenantlessService) SignVtxos(ctx context.Context, forfeitTxs []string) error {
	return s.forfeitTxs.sign(forfeitTxs)
}

func (s *covenantlessService) ListVtxos(ctx context.Context, pubkey *secp256k1.PublicKey) ([]domain.Vtxo, []domain.Vtxo, error) {
	pk := hex.EncodeToString(pubkey.SerializeCompressed())
	return s.repoManager.Vtxos().GetAllVtxos(ctx, pk)
}

func (s *covenantlessService) GetEventsChannel(ctx context.Context) <-chan interface{} {
	return s.eventsCh
}

func (s *covenantlessService) GetRoundByTxid(ctx context.Context, poolTxid string) (*domain.Round, error) {
	return s.repoManager.Rounds().GetRoundWithTxid(ctx, poolTxid)
}

func (s *covenantlessService) GetRoundById(ctx context.Context, id string) (*domain.Round, error) {
	return s.repoManager.Rounds().GetRoundWithId(ctx, id)
}

func (s *covenantlessService) GetCurrentRound(ctx context.Context) (*domain.Round, error) {
	return domain.NewRoundFromEvents(s.currentRound.Events()), nil
}

func (s *covenantlessService) GetInfo(ctx context.Context) (*ServiceInfo, error) {
	pubkey := hex.EncodeToString(s.pubkey.SerializeCompressed())

	return &ServiceInfo{
		PubKey:              pubkey,
		RoundLifetime:       s.roundLifetime,
		UnilateralExitDelay: s.unilateralExitDelay,
		RoundInterval:       s.roundInterval,
		Network:             s.network.Name,
		MinRelayFee:         int64(s.minRelayFee),
	}, nil
}

// TODO clArk changes the onboard flow (2 rounds ?)
func (s *covenantlessService) Onboard(
	ctx context.Context, boardingTx string,
	congestionTree tree.CongestionTree, userPubkey *secp256k1.PublicKey,
) error {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(boardingTx), true)
	if err != nil {
		return fmt.Errorf("failed to parse boarding tx: %s", err)
	}

	if err := bitcointree.ValidateCongestionTree(
		congestionTree, boardingTx, s.pubkey, s.roundLifetime, int64(s.minRelayFee),
	); err != nil {
		return err
	}

	extracted, err := psbt.Extract(ptx)
	if err != nil {
		return fmt.Errorf("failed to extract boarding tx: %s", err)
	}

	var serialized bytes.Buffer

	if err := extracted.Serialize(&serialized); err != nil {
		return fmt.Errorf("failed to serialize boarding tx: %s", err)
	}

	txid, err := s.wallet.BroadcastTransaction(ctx, hex.EncodeToString(serialized.Bytes()))
	if err != nil {
		return fmt.Errorf("failed to broadcast boarding tx: %s", err)
	}

	log.Debugf("broadcasted boarding tx %s", txid)

	s.onboardingCh <- onboarding{
		tx:             boardingTx,
		congestionTree: congestionTree,
		userPubkey:     userPubkey,
	}

	return nil
}

func (s *covenantlessService) IsCovenantLess() bool {
	return true
}

func (s *covenantlessService) RegisterCosignerPubkey(ctx context.Context, paymentId string, pubkey *secp256k1.PublicKey) error {
	return s.paymentRequests.pushEphemeralKey(paymentId, pubkey)
}

func (s *covenantlessService) RegisterCosignerNonces(
	ctx context.Context, roundID string, pubkey *secp256k1.PublicKey, nonces bitcointree.TreeNonces,
) error {
	session, ok := s.treeSigningSessions[roundID]
	if !ok {
		return fmt.Errorf(`signing session not found for round "%s"`, roundID)
	}

	session.lock.Lock()
	defer session.lock.Unlock()

	if _, ok := session.nonces[pubkey]; ok {
		return nil
	}

	session.nonces[pubkey] = nonces

	if len(session.nonces) == session.nbCosigners {
		session.nonceDoneC <- struct{}{}
	}

	return nil
}

func (s *covenantlessService) RegisterCosignerSignatures(
	ctx context.Context, roundID string, pubkey *secp256k1.PublicKey, signatures bitcointree.TreePartialSigs,
) error {
	session, ok := s.treeSigningSessions[roundID]
	if !ok {
		return fmt.Errorf(`signing session not found for round "%s"`, roundID)
	}

	session.lock.Lock()
	defer session.lock.Unlock()

	if _, ok := session.signatures[pubkey]; ok {
		return nil
	}

	session.signatures[pubkey] = signatures

	if len(session.signatures) == session.nbCosigners {
		session.sigDoneC <- struct{}{}
	}

	return nil
}

func (s *covenantlessService) start() {
	s.startRound()
}

func (s *covenantlessService) startRound() {
	round := domain.NewRound(dustAmount) // TODO dynamic dust amount?
	//nolint:all
	round.StartRegistration()
	s.currentRound = round

	defer func() {
		time.Sleep(time.Duration(s.roundInterval/2) * time.Second)
		s.startFinalization()
	}()

	log.Debugf("started registration stage for new round: %s", round.Id)
}

func (s *covenantlessService) startFinalization() {
	ctx := context.Background()
	round := s.currentRound

	var roundAborted bool
	defer func() {
		if roundAborted {
			s.startRound()
			return
		}

		if err := s.saveEvents(ctx, round.Id, round.Events()); err != nil {
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
		roundAborted = true
		err := fmt.Errorf("no payments registered")
		round.Fail(fmt.Errorf("round aborted: %s", err))
		log.WithError(err).Debugf("round %s aborted", round.Id)
		return
	}
	if num > paymentsThreshold {
		num = paymentsThreshold
	}
	payments, cosigners := s.paymentRequests.pop(num)
	if len(payments) > len(cosigners) {
		roundAborted = true
		err := fmt.Errorf("missing ephemeral key for payments")
		round.Fail(fmt.Errorf("round aborted: %s", err))
		log.WithError(err).Debugf("round %s aborted", round.Id)
		return
	}

	if _, err := round.RegisterPayments(payments); err != nil {
		roundAborted = true
		round.Fail(fmt.Errorf("failed to register payments: %s", err))
		log.WithError(err).Warn("failed to register payments")
		return
	}

	sweptRounds, err := s.repoManager.Rounds().GetSweptRounds(ctx)
	if err != nil {
		roundAborted = true
		round.Fail(fmt.Errorf("failed to retrieve swept rounds: %s", err))
		log.WithError(err).Warn("failed to retrieve swept rounds")
		return
	}

	ephemeralKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		roundAborted = true
		round.Fail(fmt.Errorf("failed to generate ephemeral key: %s", err))
		log.WithError(err).Warn("failed to generate ephemeral key")
		return
	}

	cosigners = append(cosigners, ephemeralKey.PubKey())

	unsignedPoolTx, tree, connectorAddress, err := s.builder.BuildPoolTx(s.pubkey, payments, s.minRelayFee, sweptRounds, cosigners...)
	if err != nil {
		roundAborted = true
		round.Fail(fmt.Errorf("failed to create pool tx: %s", err))
		log.WithError(err).Warn("failed to create pool tx")
		return
	}
	log.Debugf("pool tx created for round %s", round.Id)

	if len(tree) > 0 {
		signingSession := newMusigSigningSession(len(cosigners))
		s.treeSigningSessions[round.Id] = signingSession
		defer delete(s.treeSigningSessions, round.Id)

		// send back the unsigned tree & all cosigners pubkeys
		go s.propagateRoundSigningStartedEvent(tree, cosigners)

		noncesTimer := time.NewTimer(time.Duration((s.roundInterval/2)-1) * time.Second)
		defer noncesTimer.Stop()

		sweepClosure := bitcointree.CSVSigClosure{
			Pubkey:  s.pubkey,
			Seconds: uint(s.roundLifetime),
		}

		sweepTapLeaf, err := sweepClosure.Leaf()
		if err != nil {
			return
		}

		sweepTapTree := txscript.AssembleTaprootScriptTree(*sweepTapLeaf)
		root := sweepTapTree.RootNode.TapHash()

		coordinator, err := s.createTreeCoordinatorSession(tree, cosigners, root)
		if err != nil {
			roundAborted = true
			round.Fail(fmt.Errorf("failed to create tree coordinator: %s", err))
			log.WithError(err).Warn("failed to create tree coordinator")
			return
		}

		aspSignerSession := bitcointree.NewTreeSignerSession(
			ephemeralKey, tree, int64(s.minRelayFee), root.CloneBytes(),
		)

		nonces, err := aspSignerSession.GetNonces()
		if err != nil {
			roundAborted = true
			round.Fail(fmt.Errorf("failed to get nonces: %s", err))
			log.WithError(err).Warn("failed to get nonces")
			return
		}

		if err := coordinator.AddNonce(ephemeralKey.PubKey(), nonces); err != nil {
			roundAborted = true
			round.Fail(fmt.Errorf("failed to add nonce: %s", err))
			log.WithError(err).Warn("failed to add nonce")
			return
		}

		select {
		case <-noncesTimer.C:
			roundAborted = true
			round.Fail(fmt.Errorf("musig2 signing session timed out (nonce collection)"))
			log.Warn("musig2 signing session timed out (nonce collection)")
			return
		case <-signingSession.nonceDoneC:
			for pubkey, nonce := range signingSession.nonces {
				if err := coordinator.AddNonce(pubkey, nonce); err != nil {
					roundAborted = true
					round.Fail(fmt.Errorf("failed to add nonce: %s", err))
					log.WithError(err).Warn("failed to add nonce")
					return
				}
			}
		}

		aggragatedNonces, err := coordinator.AggregateNonces()
		if err != nil {
			roundAborted = true
			round.Fail(fmt.Errorf("failed to aggregate nonces: %s", err))
			log.WithError(err).Warn("failed to aggregate nonces")
			return
		}

		go s.propagateRoundSigningNoncesGeneratedEvent(aggragatedNonces)

		signaturesTimer := time.NewTimer(time.Duration((s.roundInterval/2)-1) * time.Second)
		defer signaturesTimer.Stop()

		if err := aspSignerSession.SetKeys(cosigners, aggragatedNonces); err != nil {
			roundAborted = true
			round.Fail(fmt.Errorf("failed to set keys: %s", err))
			log.WithError(err).Warn("failed to set keys")
			return
		}

		select {
		case <-signaturesTimer.C:
			roundAborted = true
			round.Fail(fmt.Errorf("musig2 signing session timed out (signatures)"))
			log.Warn("musig2 signing session timed out (signatures)")
			return
		case <-signingSession.sigDoneC:
			for pubkey, sig := range signingSession.signatures {
				if err := coordinator.AddSig(pubkey, sig); err != nil {
					roundAborted = true
					round.Fail(fmt.Errorf("failed to add signature: %s", err))
					log.WithError(err).Warn("failed to add signature")
					return
				}
			}
		}

		signedTree, err := coordinator.SignTree()
		if err != nil {
			round.Fail(fmt.Errorf("failed to sign tree: %s", err))
			log.WithError(err).Warn("failed to sign tree")
			return
		}

		tree = signedTree
	}

	connectors, forfeitTxs, err := s.builder.BuildForfeitTxs(s.pubkey, unsignedPoolTx, payments, s.minRelayFee)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create connectors and forfeit txs: %s", err))
		log.WithError(err).Warn("failed to create connectors and forfeit txs")
		return
	}

	log.Debugf("forfeit transactions created for round %s", round.Id)

	if _, err := round.StartFinalization(
		connectorAddress, connectors, tree, unsignedPoolTx,
	); err != nil {
		round.Fail(fmt.Errorf("failed to start finalization: %s", err))
		log.WithError(err).Warn("failed to start finalization")
		return
	}

	s.forfeitTxs.push(forfeitTxs)

	log.Debugf("started finalization stage for round: %s", round.Id)
}

func (s *covenantlessService) propagateRoundSigningStartedEvent(
	unsignedCongestionTree tree.CongestionTree, cosigners []*secp256k1.PublicKey,
) {
	s.eventsCh <- covenantlessevent.RoundSigningStarted{
		Id:                     s.currentRound.Id,
		UnsignedCongestionTree: unsignedCongestionTree,
		Cosigners:              cosigners,
	}
}

func (s *covenantlessService) propagateRoundSigningNoncesGeneratedEvent(aggragatedNonces bitcointree.TreeNonces) {
	s.eventsCh <- covenantlessevent.RoundSigningNoncesGenerated{
		Id:     s.currentRound.Id,
		Nonces: aggragatedNonces,
	}
}

func (s *covenantlessService) createTreeCoordinatorSession(
	congestionTree tree.CongestionTree, cosigners []*secp256k1.PublicKey, root chainhash.Hash,
) (bitcointree.CoordinatorSession, error) {

	return bitcointree.NewTreeCoordinatorSession(
		congestionTree, int64(s.minRelayFee), root.CloneBytes(), cosigners,
	)
}

func (s *covenantlessService) finalizeRound() {
	defer s.startRound()

	ctx := context.Background()
	round := s.currentRound
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
	signedPoolTx, err := s.wallet.SignTransaction(ctx, round.UnsignedTx, true)
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

func (s *covenantlessService) listenToOnboarding() {
	for onboarding := range s.onboardingCh {
		go s.handleOnboarding(onboarding)
	}
}

func (s *covenantlessService) handleOnboarding(onboarding onboarding) {
	ctx := context.Background()

	ptx, _ := psbt.NewFromRawBytes(strings.NewReader(onboarding.tx), true)
	txid := ptx.UnsignedTx.TxHash().String()

	// wait for the tx to be confirmed with a timeout
	timeout := time.NewTimer(15 * time.Minute)
	defer timeout.Stop()

	isConfirmed := false

	for !isConfirmed {
		select {
		case <-timeout.C:
			log.WithError(fmt.Errorf("operation timed out")).Warnf("failed to get confirmation for boarding tx %s", txid)
			return
		default:
			var err error
			isConfirmed, _, err = s.wallet.IsTransactionConfirmed(ctx, txid)
			if err != nil {
				log.WithError(err).Warn("failed to check tx confirmation")
			}

			if err != nil || !isConfirmed {
				log.Debugf("waiting for boarding tx %s to be confirmed", txid)
				time.Sleep(5 * time.Second)
			}
		}
	}

	log.Debugf("boarding tx %s confirmed", txid)

	pubkey := hex.EncodeToString(onboarding.userPubkey.SerializeCompressed())
	payments := getPaymentsFromOnboardingBitcoin(onboarding.congestionTree, pubkey)
	round := domain.NewFinalizedRound(
		dustAmount, pubkey, txid, onboarding.tx, onboarding.congestionTree, payments,
	)
	if err := s.saveEvents(ctx, round.Id, round.Events()); err != nil {
		log.WithError(err).Warn("failed to store new round events")
		return
	}
}

func (s *covenantlessService) listenToScannerNotifications() {
	ctx := context.Background()
	chVtxos := s.scanner.GetNotificationChannel(ctx)

	mutx := &sync.Mutex{}
	for vtxoKeys := range chVtxos {
		go func(vtxoKeys map[string]ports.VtxoWithValue) {
			vtxosRepo := s.repoManager.Vtxos()
			roundRepo := s.repoManager.Rounds()

			for _, v := range vtxoKeys {
				// redeem
				vtxos, err := vtxosRepo.GetVtxos(ctx, []domain.VtxoKey{v.VtxoKey})
				if err != nil {
					log.WithError(err).Warn("failed to retrieve vtxos, skipping...")
					continue
				}

				vtxo := vtxos[0]

				if vtxo.Redeemed {
					continue
				}

				if err := s.repoManager.Vtxos().RedeemVtxos(
					ctx, []domain.VtxoKey{vtxo.VtxoKey},
				); err != nil {
					log.WithError(err).Warn("failed to redeem vtxos, retrying...")
					continue
				}
				log.Debugf("vtxo %s redeemed", vtxo.Txid)

				if !vtxo.Spent {
					continue
				}

				log.Debugf("fraud detected on vtxo %s", vtxo.Txid)

				round, err := roundRepo.GetRoundWithTxid(ctx, vtxo.SpentBy)
				if err != nil {
					log.WithError(err).Warn("failed to retrieve round")
					continue
				}

				mutx.Lock()
				defer mutx.Unlock()

				connectorTxid, connectorVout, err := s.getNextConnector(ctx, *round)
				if err != nil {
					log.WithError(err).Warn("failed to retrieve next connector")
					continue
				}

				forfeitTx, err := findForfeitTxBitcoin(round.ForfeitTxs, connectorTxid, connectorVout, vtxo.Txid)
				if err != nil {
					log.WithError(err).Warn("failed to retrieve forfeit tx")
					continue
				}

				if err := s.wallet.LockConnectorUtxos(ctx, []ports.TxOutpoint{txOutpoint{connectorTxid, connectorVout}}); err != nil {
					log.WithError(err).Warn("failed to lock connector utxos")
					continue
				}

				signedForfeitTx, err := s.wallet.SignTransaction(ctx, forfeitTx, false)
				if err != nil {
					log.WithError(err).Warn("failed to sign connector input in forfeit tx")
					continue
				}

				signedForfeitTx, err = s.wallet.SignTransactionTapscript(ctx, signedForfeitTx, []int{1})
				if err != nil {
					log.WithError(err).Warn("failed to sign vtxo input in forfeit tx")
					continue
				}

				forfeitTxHex, err := s.builder.FinalizeAndExtractForfeit(signedForfeitTx)
				if err != nil {
					log.WithError(err).Warn("failed to finalize forfeit tx")
					continue
				}

				forfeitTxid, err := s.wallet.BroadcastTransaction(ctx, forfeitTxHex)
				if err != nil {
					log.WithError(err).Warn("failed to broadcast forfeit tx")
					continue
				}

				log.Debugf("broadcasted forfeit tx %s", forfeitTxid)
			}
		}(vtxoKeys)
	}
}

func (s *covenantlessService) getNextConnector(
	ctx context.Context,
	round domain.Round,
) (string, uint32, error) {
	utxos, err := s.wallet.ListConnectorUtxos(ctx, round.ConnectorAddress)
	if err != nil {
		return "", 0, err
	}

	// if we do not find any utxos, we make sure to wait for the connector outpoint to be confirmed then we retry
	if len(utxos) <= 0 {
		if err := s.wallet.WaitForSync(ctx, round.Txid); err != nil {
			return "", 0, err
		}

		utxos, err = s.wallet.ListConnectorUtxos(ctx, round.ConnectorAddress)
		if err != nil {
			return "", 0, err
		}
	}

	// search for an already existing connector
	for _, u := range utxos {
		if u.GetValue() == 450 {
			return u.GetTxid(), u.GetIndex(), nil
		}
	}

	for _, u := range utxos {
		if u.GetValue() > 450 {
			for _, b64 := range round.Connectors {
				ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
				if err != nil {
					return "", 0, err
				}

				for _, i := range ptx.UnsignedTx.TxIn {
					if i.PreviousOutPoint.Hash.String() == u.GetTxid() && i.PreviousOutPoint.Index == u.GetIndex() {
						connectorOutpoint := txOutpoint{u.GetTxid(), u.GetIndex()}

						if err := s.wallet.LockConnectorUtxos(ctx, []ports.TxOutpoint{connectorOutpoint}); err != nil {
							return "", 0, err
						}

						// sign & broadcast the connector tx
						signedConnectorTx, err := s.wallet.SignTransaction(ctx, b64, true)
						if err != nil {
							return "", 0, err
						}

						connectorTxid, err := s.wallet.BroadcastTransaction(ctx, signedConnectorTx)
						if err != nil {
							return "", 0, err
						}
						log.Debugf("broadcasted connector tx %s", connectorTxid)

						// wait for the connector tx to be in the mempool
						if err := s.wallet.WaitForSync(ctx, connectorTxid); err != nil {
							return "", 0, err
						}

						return connectorTxid, 0, nil
					}
				}
			}
		}
	}

	return "", 0, fmt.Errorf("no connector utxos found")
}

func (s *covenantlessService) updateVtxoSet(round *domain.Round) {
	// Update the vtxo set only after a round is finalized.
	if !round.IsEnded() {
		return
	}

	ctx := context.Background()
	repo := s.repoManager.Vtxos()
	spentVtxos := getSpentVtxos(round.Payments)
	if len(spentVtxos) > 0 {
		for {
			if err := repo.SpendVtxos(ctx, spentVtxos, round.Txid); err != nil {
				log.WithError(err).Warn("failed to add new vtxos, retrying soon")
				time.Sleep(100 * time.Millisecond)
				continue
			}
			log.Debugf("spent %d vtxos", len(spentVtxos))
			break
		}
	}

	newVtxos := s.getNewVtxos(round)
	if len(newVtxos) > 0 {
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
}

func (s *covenantlessService) propagateEvents(round *domain.Round) {
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

func (s *covenantlessService) scheduleSweepVtxosForRound(round *domain.Round) {
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

func (s *covenantlessService) getNewVtxos(round *domain.Round) []domain.Vtxo {
	if len(round.CongestionTree) <= 0 {
		return nil
	}

	leaves := round.CongestionTree.Leaves()
	vtxos := make([]domain.Vtxo, 0)
	for _, node := range leaves {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
		if err != nil {
			log.WithError(err).Warn("failed to parse tx")
			continue
		}
		for i, out := range tx.UnsignedTx.TxOut {
			for _, p := range round.Payments {
				var pubkey string
				found := false
				for _, r := range p.Receivers {
					if r.IsOnchain() {
						continue
					}

					buf, _ := hex.DecodeString(r.Pubkey)
					pk, _ := secp256k1.ParsePubKey(buf)
					script, err := s.builder.GetVtxoScript(pk, s.pubkey)
					if err != nil {
						log.WithError(err).Warn("failed to get vtxo script")
						continue
					}

					if bytes.Equal(script, out.PkScript) {
						found = true
						pubkey = r.Pubkey
						break
					}
				}
				if found {
					vtxos = append(vtxos, domain.Vtxo{
						VtxoKey:  domain.VtxoKey{Txid: node.Txid, VOut: uint32(i)},
						Receiver: domain.Receiver{Pubkey: pubkey, Amount: uint64(out.Value)},
						PoolTx:   round.Txid,
					})
					break
				}
			}
		}
	}
	return vtxos
}

func (s *covenantlessService) startWatchingVtxos(vtxos []domain.Vtxo) error {
	scripts, err := s.extractVtxosScripts(vtxos)
	if err != nil {
		return err
	}

	return s.scanner.WatchScripts(context.Background(), scripts)
}

func (s *covenantlessService) stopWatchingVtxos(vtxos []domain.Vtxo) {
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

func (s *covenantlessService) restoreWatchingVtxos() error {
	sweepableRounds, err := s.repoManager.Rounds().GetSweepableRounds(context.Background())
	if err != nil {
		return err
	}

	vtxos := make([]domain.Vtxo, 0)

	for _, round := range sweepableRounds {
		fromRound, err := s.repoManager.Vtxos().GetVtxosForRound(
			context.Background(), round.Txid,
		)
		if err != nil {
			log.WithError(err).Warnf("failed to retrieve vtxos for round %s", round.Txid)
			continue
		}
		for _, v := range fromRound {
			if !v.Swept && !v.Redeemed {
				vtxos = append(vtxos, v)
			}
		}
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

func (s *covenantlessService) extractVtxosScripts(vtxos []domain.Vtxo) ([]string, error) {
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

func (s *covenantlessService) saveEvents(
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

func getPaymentsFromOnboardingBitcoin(
	congestionTree tree.CongestionTree, userKey string,
) []domain.Payment {
	leaves := congestionTree.Leaves()
	receivers := make([]domain.Receiver, 0, len(leaves))
	for _, node := range leaves {
		ptx, _ := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)

		receiver := domain.Receiver{
			Pubkey: userKey,
			Amount: uint64(ptx.UnsignedTx.TxOut[0].Value),
		}
		receivers = append(receivers, receiver)
	}
	payment := domain.NewPaymentUnsafe(nil, receivers)
	return []domain.Payment{*payment}
}

func findForfeitTxBitcoin(
	forfeits []string, connectorTxid string, connectorVout uint32, vtxoTxid string,
) (string, error) {
	for _, forfeit := range forfeits {
		forfeitTx, err := psbt.NewFromRawBytes(strings.NewReader(forfeit), true)
		if err != nil {
			return "", err
		}

		connector := forfeitTx.UnsignedTx.TxIn[0]
		vtxoInput := forfeitTx.UnsignedTx.TxIn[1]

		if connector.PreviousOutPoint.String() == connectorTxid &&
			connector.PreviousOutPoint.Index == connectorVout &&
			vtxoInput.PreviousOutPoint.String() == vtxoTxid {
			return forfeit, nil
		}
	}

	return "", fmt.Errorf("forfeit tx not found")
}

// musigSigningSession is a struct that holds the state of nonces and signatures in order to sign the congestion tree
type musigSigningSession struct {
	lock        sync.Mutex
	nbCosigners int
	nonces      map[*secp256k1.PublicKey]bitcointree.TreeNonces
	nonceDoneC  chan struct{}

	signatures map[*secp256k1.PublicKey]bitcointree.TreePartialSigs
	sigDoneC   chan struct{}
}

func newMusigSigningSession(nbCosigners int) *musigSigningSession {
	return &musigSigningSession{
		nonces:     make(map[*secp256k1.PublicKey]bitcointree.TreeNonces),
		nonceDoneC: make(chan struct{}),

		signatures:  make(map[*secp256k1.PublicKey]bitcointree.TreePartialSigs),
		sigDoneC:    make(chan struct{}),
		lock:        sync.Mutex{},
		nbCosigners: nbCosigners,
	}
}
