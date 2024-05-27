package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
)

var (
	paymentsThreshold = int64(128)
	dustAmount        = uint64(450)
)

type ServiceInfo struct {
	PubKey              string
	RoundLifetime       int64
	UnilateralExitDelay int64
	RoundInterval       int64
	Network             string
	MinRelayFee         int64
}

type Service interface {
	Start() error
	Stop()
	SpendVtxos(ctx context.Context, inputs []domain.VtxoKey) (string, error)
	ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver) error
	SignVtxos(ctx context.Context, forfeitTxs []string) error
	GetRoundByTxid(ctx context.Context, poolTxid string) (*domain.Round, error)
	GetCurrentRound(ctx context.Context) (*domain.Round, error)
	GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent
	UpdatePaymentStatus(ctx context.Context, id string) (unsignedForfeitTxs []string, err error)
	ListVtxos(ctx context.Context, pubkey *secp256k1.PublicKey) ([]domain.Vtxo, []domain.Vtxo, error)
	GetInfo(ctx context.Context) (*ServiceInfo, error)
	Onboard(ctx context.Context, boardingTx string, congestionTree tree.CongestionTree, userPubkey *secp256k1.PublicKey) error
	TrustedOnboarding(ctx context.Context, userPubKey *secp256k1.PublicKey, onboardingAmount uint64) (string, uint64, error)
}

type onboarding struct {
	tx             string
	congestionTree tree.CongestionTree
	userPubkey     *secp256k1.PublicKey
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

	eventsCh     chan domain.RoundEvent
	onboardingCh chan onboarding

	trustedOnboardingScriptLock *sync.Mutex
	trustedOnboardingScripts    map[string]*secp256k1.PublicKey
}

func NewService(
	network common.Network, onchainNetwork network.Network,
	roundInterval, roundLifetime, unilateralExitDelay int64, minRelayFee uint64,
	walletSvc ports.WalletService, repoManager ports.RepoManager,
	builder ports.TxBuilder, scanner ports.BlockchainScanner,
	scheduler ports.SchedulerService,
) (Service, error) {
	eventsCh := make(chan domain.RoundEvent)
	onboardingCh := make(chan onboarding)
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

func (s *service) UpdatePaymentStatus(_ context.Context, id string) ([]string, error) {
	err := s.paymentRequests.updatePingTimestamp(id)
	if err != nil {
		if _, ok := err.(errPaymentNotFound); ok {
			return s.forfeitTxs.view(), nil
		}

		return nil, err
	}

	return nil, nil
}

func (s *service) SignVtxos(ctx context.Context, forfeitTxs []string) error {
	return s.forfeitTxs.sign(forfeitTxs)
}

func (s *service) ListVtxos(ctx context.Context, pubkey *secp256k1.PublicKey) ([]domain.Vtxo, []domain.Vtxo, error) {
	pk := hex.EncodeToString(pubkey.SerializeCompressed())
	return s.repoManager.Vtxos().GetAllVtxos(ctx, pk)
}

func (s *service) GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent {
	return s.eventsCh
}

func (s *service) GetRoundByTxid(ctx context.Context, poolTxid string) (*domain.Round, error) {
	return s.repoManager.Rounds().GetRoundWithTxid(ctx, poolTxid)
}

func (s *service) GetCurrentRound(ctx context.Context) (*domain.Round, error) {
	return s.repoManager.Rounds().GetCurrentRound(ctx)
}

func (s *service) GetInfo(ctx context.Context) (*ServiceInfo, error) {
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

func (s *service) Onboard(
	ctx context.Context, boardingTx string,
	congestionTree tree.CongestionTree, userPubkey *secp256k1.PublicKey,
) error {
	ptx, err := psetv2.NewPsetFromBase64(boardingTx)
	if err != nil {
		return fmt.Errorf("failed to parse boarding tx: %s", err)
	}

	if err := tree.ValidateCongestionTree(
		congestionTree, boardingTx, s.pubkey, s.roundLifetime,
	); err != nil {
		return err
	}

	extracted, err := psetv2.Extract(ptx)
	if err != nil {
		return fmt.Errorf("failed to extract boarding tx: %s", err)
	}

	boardingTxHex, err := extracted.ToHex()
	if err != nil {
		return fmt.Errorf("failed to convert boarding tx to hex: %s", err)
	}

	txid, err := s.wallet.BroadcastTransaction(ctx, boardingTxHex)
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

func (s *service) TrustedOnboarding(
	ctx context.Context, userPubKey *secp256k1.PublicKey, onboardingAmount uint64,
) (string, uint64, error) {
	congestionTreeLeaf := tree.Receiver{
		Pubkey: hex.EncodeToString(userPubKey.SerializeCompressed()),
		Amount: onboardingAmount,
	}

	_, sharedOutputScript, sharedOutputAmount, err := tree.CraftCongestionTree(
		s.onchainNework.AssetID, s.pubkey, []tree.Receiver{congestionTreeLeaf},
		s.minRelayFee, s.roundLifetime, s.unilateralExitDelay,
	)
	if err != nil {
		return "", 0, err
	}

	pay, err := payment.FromScript(sharedOutputScript, &s.onchainNework, nil)
	if err != nil {
		return "", 0, err
	}

	address, err := pay.TaprootAddress()
	if err != nil {
		return "", 0, err
	}

	s.trustedOnboardingScriptLock.Lock()

	script := hex.EncodeToString(sharedOutputScript)
	s.trustedOnboardingScripts[script] = userPubKey

	s.trustedOnboardingScriptLock.Unlock()

	if err := s.scanner.WatchScripts(ctx, []string{script}); err != nil {
		return "", 0, err
	}

	return address, sharedOutputAmount, nil
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

	sweptRounds, err := s.repoManager.Rounds().GetSweptRounds(ctx)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to retrieve swept rounds: %s", err))
		log.WithError(err).Warn("failed to retrieve swept rounds")
		return
	}

	unsignedPoolTx, tree, connectorAddress, err := s.builder.BuildPoolTx(s.pubkey, payments, s.minRelayFee, sweptRounds)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to create pool tx: %s", err))
		log.WithError(err).Warn("failed to create pool tx")
		return
	}

	log.Debugf("pool tx created for round %s", round.Id)

	connectors, forfeitTxs, err := s.builder.BuildForfeitTxs(s.pubkey, unsignedPoolTx, payments, s.minRelayFee)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to create connectors and forfeit txs: %s", err))
		log.WithError(err).Warn("failed to create connectors and forfeit txs")
		return
	}

	log.Debugf("forfeit transactions created for round %s", round.Id)

	events, err := round.StartFinalization(connectorAddress, connectors, tree, unsignedPoolTx)
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

func (s *service) listenToOnboarding() {
	for onboarding := range s.onboardingCh {
		go s.handleOnboarding(onboarding)
	}
}

func (s *service) handleOnboarding(onboarding onboarding) {
	ctx := context.Background()

	ptx, _ := psetv2.NewPsetFromBase64(onboarding.tx)
	utx, _ := psetv2.Extract(ptx)
	txid := utx.TxHash().String()

	// wait for the tx to be confirmed with a timeout
	timeout := time.NewTimer(5 * time.Minute)
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
				time.Sleep(5 * time.Second)
			}
		}
	}

	pubkey := hex.EncodeToString(onboarding.userPubkey.SerializeCompressed())
	payments := getPaymentsFromOnboarding(onboarding.congestionTree, pubkey)
	round := domain.NewFinalizedRound(
		dustAmount, pubkey, txid, onboarding.tx, onboarding.congestionTree, payments,
	)
	if err := s.saveEvents(ctx, round.Id, round.Events()); err != nil {
		log.WithError(err).Warn("failed to store new round events")
		return
	}
}

func (s *service) listenToScannerNotifications() {
	ctx := context.Background()
	chVtxos := s.scanner.GetNotificationChannel(ctx)

	mutx := &sync.Mutex{}
	for vtxoKeys := range chVtxos {
		go func(vtxoKeys map[string]ports.VtxoWithValue) {
			vtxosRepo := s.repoManager.Vtxos()
			roundRepo := s.repoManager.Rounds()

			for script, v := range vtxoKeys {
				if userPubkey, ok := s.trustedOnboardingScripts[script]; ok {
					// onboarding
					defer func() {
						s.trustedOnboardingScriptLock.Lock()
						delete(s.trustedOnboardingScripts, script)
						s.trustedOnboardingScriptLock.Unlock()
					}()

					congestionTreeLeaf := tree.Receiver{
						Pubkey: hex.EncodeToString(userPubkey.SerializeCompressed()),
						Amount: v.Value - s.minRelayFee,
					}

					treeFactoryFn, sharedOutputScript, sharedOutputAmount, err := tree.CraftCongestionTree(
						s.onchainNework.AssetID, s.pubkey, []tree.Receiver{congestionTreeLeaf},
						s.minRelayFee, s.roundLifetime, s.unilateralExitDelay,
					)
					if err != nil {
						log.WithError(err).Warn("failed to craft onboarding congestion tree")
						return
					}

					congestionTree, err := treeFactoryFn(
						psetv2.InputArgs{
							Txid:    v.Txid,
							TxIndex: v.VOut,
						},
					)
					if err != nil {
						log.WithError(err).Warn("failed to build onboarding congestion tree")
						return
					}

					if sharedOutputAmount != v.Value {
						log.Errorf("shared output amount mismatch, expected %d, got %d", sharedOutputAmount, v.Value)
						return
					}

					precomputedScript, _ := hex.DecodeString(script)

					if !bytes.Equal(sharedOutputScript, precomputedScript) {
						log.Errorf("shared output script mismatch, expected %x, got %x", sharedOutputScript, precomputedScript)
						return
					}

					pubkey := hex.EncodeToString(userPubkey.SerializeCompressed())
					payments := getPaymentsFromOnboarding(congestionTree, pubkey)
					round := domain.NewFinalizedRound(
						dustAmount, pubkey, v.Txid, "", congestionTree, payments,
					)
					if err := s.saveEvents(ctx, round.Id, round.Events()); err != nil {
						log.WithError(err).Warn("failed to store new round events")
						return
					}

					return
				}

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

				forfeitTx, err := findForfeitTx(round.ForfeitTxs, connectorTxid, connectorVout, vtxo.Txid)
				if err != nil {
					log.WithError(err).Warn("failed to retrieve forfeit tx")
					continue
				}

				if err := s.wallet.LockConnectorUtxos(ctx, []ports.TxOutpoint{txOutpoint{connectorTxid, connectorVout}}); err != nil {
					log.WithError(err).Warn("failed to lock connector utxos")
					continue
				}

				signedForfeitTx, err := s.wallet.SignPset(ctx, forfeitTx, false)
				if err != nil {
					log.WithError(err).Warn("failed to sign connector input in forfeit tx")
					continue
				}

				signedForfeitTx, err = s.wallet.SignPsetWithKey(ctx, signedForfeitTx, []int{1})
				if err != nil {
					log.WithError(err).Warn("failed to sign vtxo input in forfeit tx")
					continue
				}

				forfeitTxHex, err := finalizeAndExtractForfeit(signedForfeitTx)
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

func (s *service) getNextConnector(
	ctx context.Context,
	round domain.Round,
) (string, uint32, error) {
	connectorTx, err := psetv2.NewPsetFromBase64(round.Connectors[0])
	if err != nil {
		return "", 0, err
	}

	prevout := connectorTx.Inputs[0].WitnessUtxo
	if prevout == nil {
		return "", 0, fmt.Errorf("connector prevout not found")
	}

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
				pset, err := psetv2.NewPsetFromBase64(b64)
				if err != nil {
					return "", 0, err
				}

				for _, i := range pset.Inputs {
					if chainhash.Hash(i.PreviousTxid).String() == u.GetTxid() && i.PreviousTxIndex == u.GetIndex() {
						connectorOutpoint := newOutpointFromPsetInput(pset.Inputs[0])

						if err := s.wallet.LockConnectorUtxos(ctx, []ports.TxOutpoint{connectorOutpoint}); err != nil {
							return "", 0, err
						}

						// sign & broadcast the connector tx
						signedConnectorTx, err := s.wallet.SignPset(ctx, b64, true)
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
	if len(round.CongestionTree) <= 0 {
		return nil
	}

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

func finalizeAndExtractForfeit(b64 string) (string, error) {
	p, err := psetv2.NewPsetFromBase64(b64)
	if err != nil {
		return "", err
	}

	// finalize connector input
	if err := psetv2.FinalizeAll(p); err != nil {
		return "", err
	}

	// extract the forfeit tx
	extracted, err := psetv2.Extract(p)
	if err != nil {
		return "", err
	}

	return extracted.ToHex()
}

func findForfeitTx(
	forfeits []string, connectorTxid string, connectorVout uint32, vtxoTxid string,
) (string, error) {
	for _, forfeit := range forfeits {
		forfeitTx, err := psetv2.NewPsetFromBase64(forfeit)
		if err != nil {
			return "", err
		}

		connector := forfeitTx.Inputs[0]
		vtxoInput := forfeitTx.Inputs[1]

		if chainhash.Hash(connector.PreviousTxid).String() == connectorTxid &&
			connector.PreviousTxIndex == connectorVout &&
			chainhash.Hash(vtxoInput.PreviousTxid).String() == vtxoTxid {
			return forfeit, nil
		}
	}

	return "", fmt.Errorf("forfeit tx not found")
}

type txOutpoint struct {
	txid string
	vout uint32
}

func newOutpointFromPsetInput(input psetv2.Input) txOutpoint {
	return txOutpoint{
		txid: chainhash.Hash(input.PreviousTxid).String(),
		vout: input.PreviousTxIndex,
	}
}

func (outpoint txOutpoint) GetTxid() string {
	return outpoint.txid
}

func (outpoint txOutpoint) GetIndex() uint32 {
	return outpoint.vout
}
