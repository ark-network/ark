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
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
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

	eventsCh     chan domain.RoundEvent
	onboardingCh chan onboarding

	trustedOnboardingScriptLock *sync.Mutex
	trustedOnboardingScripts    map[string]*secp256k1.PublicKey
}

func NewCovenantlessService(
	network common.Network,
	roundInterval, roundLifetime, unilateralExitDelay int64, minRelayFee uint64,
	walletSvc ports.WalletService, repoManager ports.RepoManager,
	builder ports.TxBuilder, scanner ports.BlockchainScanner,
	scheduler ports.SchedulerService,
) (Service, error) {
	eventsCh := make(chan domain.RoundEvent)
	onboardingCh := make(chan onboarding)
	paymentRequests := newPaymentsMap(nil)

	forfeitTxs := newForfeitTxsMap(builder)
	pubkey, err := walletSvc.GetPubkey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pubkey: %s", err)
	}

	sweeper := newSweeper(walletSvc, repoManager, builder, scheduler)

	svc := &covenantlessService{
		network, pubkey,
		roundLifetime, roundInterval, unilateralExitDelay, minRelayFee,
		walletSvc, repoManager, builder, scanner, sweeper,
		paymentRequests, forfeitTxs, eventsCh, onboardingCh,
		&sync.Mutex{}, make(map[string]*secp256k1.PublicKey),
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

func (s *covenantlessService) UpdatePaymentStatus(_ context.Context, id string) ([]string, error) {
	err := s.paymentRequests.updatePingTimestamp(id)
	if err != nil {
		if _, ok := err.(errPaymentNotFound); ok {
			return s.forfeitTxs.view(), nil
		}

		return nil, err
	}

	return nil, nil
}

func (s *covenantlessService) SignVtxos(ctx context.Context, forfeitTxs []string) error {
	return s.forfeitTxs.sign(forfeitTxs)
}

func (s *covenantlessService) ListVtxos(ctx context.Context, pubkey *secp256k1.PublicKey) ([]domain.Vtxo, []domain.Vtxo, error) {
	pk := hex.EncodeToString(pubkey.SerializeCompressed())
	return s.repoManager.Vtxos().GetAllVtxos(ctx, pk)
}

func (s *covenantlessService) GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent {
	return s.eventsCh
}

func (s *covenantlessService) GetRoundByTxid(ctx context.Context, poolTxid string) (*domain.Round, error) {
	return s.repoManager.Rounds().GetRoundWithTxid(ctx, poolTxid)
}

func (s *covenantlessService) GetCurrentRound(ctx context.Context) (*domain.Round, error) {
	return s.repoManager.Rounds().GetCurrentRound(ctx)
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

	// if err := bitcointree.ValidateCongestionTree(
	// 	congestionTree, boardingTx, s.pubkey, s.roundLifetime, []*secp256k1.PublicKey{s.pubkey}, int64(s.minRelayFee),
	// ); err != nil {
	// 	return err
	// }

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

func (s *covenantlessService) TrustedOnboarding(
	ctx context.Context, userPubKey *secp256k1.PublicKey,
) (string, error) {
	// TODO clArk x trustedOnboding ?
	panic("not implemented")
}

func (s *covenantlessService) start() {
	s.startRound()
}

func (s *covenantlessService) startRound() {
	round := domain.NewRound(dustAmount) // TODO dynamic dust amount?
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

func (s *covenantlessService) startFinalization() {
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

	sweptRounds, err := s.repoManager.Rounds().GetSweptRounds(ctx)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to retrieve swept rounds: %s", err))
		log.WithError(err).Warn("failed to retrieve swept rounds")
		return
	}

	cosigners := make([]*secp256k1.PrivateKey, 0)
	cosignersPubKeys := make([]*secp256k1.PublicKey, 0, len(cosigners))
	for range payments {
		// TODO sender should provide the ephemeral *public* key
		ephemeralKey, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			changes = round.Fail(fmt.Errorf("failed to generate ephemeral key: %s", err))
			log.WithError(err).Warn("failed to generate ephemeral key")
			return
		}

		cosigners = append(cosigners, ephemeralKey)
		cosignersPubKeys = append(cosignersPubKeys, ephemeralKey.PubKey())
	}

	aspSigningKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to generate asp signing key: %s", err))
		log.WithError(err).Warn("failed to generate asp signing key")
		return
	}

	cosigners = append(cosigners, aspSigningKey)
	cosignersPubKeys = append(cosignersPubKeys, aspSigningKey.PubKey())

	unsignedPoolTx, tree, connectorAddress, err := s.builder.BuildPoolTx(s.pubkey, payments, s.minRelayFee, sweptRounds, cosignersPubKeys...)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to create pool tx: %s", err))
		log.WithError(err).Warn("failed to create pool tx")
		return
	}
	log.Debugf("pool tx created for round %s", round.Id)

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

	coordinator, err := s.createTreeCoordinatorSession(tree, cosignersPubKeys, root)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to create tree coordinator: %s", err))
		log.WithError(err).Warn("failed to create tree coordinator")
		return
	}

	signers := make([]bitcointree.SignerSession, 0)

	for _, seckey := range cosigners {
		signer := bitcointree.NewTreeSignerSession(
			seckey, tree, int64(s.minRelayFee), root.CloneBytes(),
		)

		// TODO nonces should be sent by the sender
		nonces, err := signer.GetNonces()
		if err != nil {
			changes = round.Fail(fmt.Errorf("failed to get nonces: %s", err))
			log.WithError(err).Warn("failed to get nonces")
			return
		}

		if err := coordinator.AddNonce(seckey.PubKey(), nonces); err != nil {
			changes = round.Fail(fmt.Errorf("failed to add nonce: %s", err))
			log.WithError(err).Warn("failed to add nonce")
			return
		}

		signers = append(signers, signer)
	}

	aggragatedNonces, err := coordinator.AggregateNonces()
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to aggregate nonces: %s", err))
		log.WithError(err).Warn("failed to aggregate nonces")
		return
	}

	// TODO aggragated nonces and public keys should be sent back to signer
	// TODO signing should be done client-side (except for the ASP)
	for i, signer := range signers {
		if err := signer.SetKeys(cosignersPubKeys, aggragatedNonces); err != nil {
			changes = round.Fail(fmt.Errorf("failed to set keys: %s", err))
			log.WithError(err).Warn("failed to set keys")
			return
		}

		sig, err := signer.Sign()
		if err != nil {
			changes = round.Fail(fmt.Errorf("failed to sign: %s", err))
			log.WithError(err).Warn("failed to sign")
			return
		}

		if err := coordinator.AddSig(cosignersPubKeys[i], sig); err != nil {
			changes = round.Fail(fmt.Errorf("failed to add sig: %s", err))
			log.WithError(err).Warn("failed to add sig")
			return
		}
	}

	signedTree, err := coordinator.SignTree()
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to sign tree: %s", err))
		log.WithError(err).Warn("failed to sign tree")
		return
	}

	connectors, forfeitTxs, err := s.builder.BuildForfeitTxs(s.pubkey, unsignedPoolTx, payments, s.minRelayFee)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to create connectors and forfeit txs: %s", err))
		log.WithError(err).Warn("failed to create connectors and forfeit txs")
		return
	}

	log.Debugf("forfeit transactions created for round %s", round.Id)

	events, err := round.StartFinalization(connectorAddress, connectors, signedTree, unsignedPoolTx)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to start finalization: %s", err))
		log.WithError(err).Warn("failed to start finalization")
		return
	}
	changes = append(changes, events...)

	s.forfeitTxs.push(forfeitTxs)

	log.Debugf("started finalization stage for round: %s", round.Id)
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
				//onboarding
				// if _, ok := s.trustedOnboardingScripts[script]; ok {
				// 	// TODO related to TrustedOnboarding
				// }

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

				if _, err := s.repoManager.Vtxos().RedeemVtxos(ctx, []domain.VtxoKey{vtxo.VtxoKey}); err != nil {
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
