package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/descriptor"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

var (
	ErrTreeSigningNotRequired = fmt.Errorf("tree signing is not required on this ark (covenant)")
)

type covenantService struct {
	network             common.Network
	pubkey              *secp256k1.PublicKey
	roundLifetime       int64
	roundInterval       int64
	unilateralExitDelay int64
	boardingExitDelay   int64

	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder
	scanner     ports.BlockchainScanner
	sweeper     *sweeper

	paymentRequests *paymentsMap
	forfeitTxs      *forfeitTxsMap

	eventsCh            chan domain.RoundEvent
	transactionEventsCh chan TransactionEvent

	currentRoundLock sync.Mutex
	currentRound     *domain.Round
	lastEvent        domain.RoundEvent
}

func NewCovenantService(
	network common.Network,
	roundInterval, roundLifetime, unilateralExitDelay, boardingExitDelay int64,
	walletSvc ports.WalletService, repoManager ports.RepoManager,
	builder ports.TxBuilder, scanner ports.BlockchainScanner,
	scheduler ports.SchedulerService,
) (Service, error) {
	pubkey, err := walletSvc.GetPubkey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pubkey: %s", err)
	}

	svc := &covenantService{
		network:             network,
		pubkey:              pubkey,
		roundLifetime:       roundLifetime,
		roundInterval:       roundInterval,
		unilateralExitDelay: unilateralExitDelay,
		boardingExitDelay:   boardingExitDelay,
		wallet:              walletSvc,
		repoManager:         repoManager,
		builder:             builder,
		scanner:             scanner,
		sweeper:             newSweeper(walletSvc, repoManager, builder, scheduler),
		paymentRequests:     newPaymentsMap(),
		forfeitTxs:          newForfeitTxsMap(builder),
		eventsCh:            make(chan domain.RoundEvent),
		transactionEventsCh: make(chan TransactionEvent),
		currentRoundLock:    sync.Mutex{},
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
	return svc, nil
}

func (s *covenantService) Start() error {
	log.Debug("starting sweeper service")
	if err := s.sweeper.start(); err != nil {
		return err
	}

	log.Debug("starting app service")
	go s.start()
	return nil
}

func (s *covenantService) Stop() {
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
}

func (s *covenantService) GetBoardingAddress(ctx context.Context, userPubkey *secp256k1.PublicKey) (string, string, error) {
	vtxoScript := &tree.DefaultVtxoScript{
		Asp:       s.pubkey,
		Owner:     userPubkey,
		ExitDelay: uint(s.boardingExitDelay),
	}

	tapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return "", "", fmt.Errorf("failed to get taproot key: %s", err)
	}

	p2tr, err := payment.FromTweakedKey(tapKey, s.onchainNetwork(), nil)
	if err != nil {
		return "", "", err
	}

	addr, err := p2tr.TaprootAddress()
	if err != nil {
		return "", "", err
	}

	return addr, vtxoScript.ToDescriptor(), nil
}

func (s *covenantService) SpendVtxos(ctx context.Context, inputs []ports.Input) (string, error) {
	vtxosInputs := make([]domain.Vtxo, 0)
	boardingInputs := make([]ports.BoardingInput, 0)

	now := time.Now().Unix()

	boardingTxs := make(map[string]*transaction.Transaction, 0) // txid -> txhex

	for _, input := range inputs {
		vtxosResult, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.VtxoKey{input.VtxoKey})
		if err != nil || len(vtxosResult) == 0 {
			// vtxo not found in db, check if it exists on-chain
			if _, ok := boardingTxs[input.Txid]; !ok {
				// check if the tx exists and is confirmed
				txhex, err := s.wallet.GetTransaction(ctx, input.Txid)
				if err != nil {
					return "", fmt.Errorf("failed to get tx %s: %s", input.Txid, err)
				}

				tx, err := transaction.NewTxFromHex(txhex)
				if err != nil {
					return "", fmt.Errorf("failed to parse tx %s: %s", input.Txid, err)
				}

				confirmed, _, blocktime, err := s.wallet.IsTransactionConfirmed(ctx, input.Txid)
				if err != nil {
					return "", fmt.Errorf("failed to check tx %s: %s", input.Txid, err)
				}

				if !confirmed {
					return "", fmt.Errorf("tx %s not confirmed", input.Txid)
				}

				// if the exit path is available, forbid registering the boarding utxo
				if blocktime+int64(s.boardingExitDelay) < now {
					return "", fmt.Errorf("tx %s expired", input.Txid)
				}

				boardingTxs[input.Txid] = tx
			}

			tx := boardingTxs[input.Txid]
			boardingInput, err := s.newBoardingInput(tx, input)
			if err != nil {
				return "", err
			}

			boardingInputs = append(boardingInputs, *boardingInput)
			continue
		}

		vtxo := vtxosResult[0]
		if vtxo.Spent {
			return "", fmt.Errorf("input %s:%d already spent", vtxo.Txid, vtxo.VOut)
		}

		if vtxo.Redeemed {
			return "", fmt.Errorf("input %s:%d already redeemed", vtxo.Txid, vtxo.VOut)
		}

		if vtxo.Swept {
			return "", fmt.Errorf("input %s:%d already swept", vtxo.Txid, vtxo.VOut)
		}

		vtxosInputs = append(vtxosInputs, vtxo)
	}

	payment, err := domain.NewPayment(vtxosInputs)
	if err != nil {
		return "", err
	}
	if err := s.paymentRequests.push(*payment, boardingInputs); err != nil {
		return "", err
	}
	return payment.Id, nil
}

func (s *covenantService) newBoardingInput(tx *transaction.Transaction, input ports.Input) (*ports.BoardingInput, error) {
	if len(tx.Outputs) <= int(input.VtxoKey.VOut) {
		return nil, fmt.Errorf("output not found")
	}

	output := tx.Outputs[input.VtxoKey.VOut]

	if len(output.RangeProof) > 0 || len(output.SurjectionProof) > 0 {
		return nil, fmt.Errorf("output is confidential")
	}

	amount, err := elementsutil.ValueFromBytes(output.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to parse value: %s", err)
	}

	boardingScript, err := tree.ParseVtxoScript(input.Descriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to parse boarding descriptor: %s", err)
	}

	tapKey, _, err := boardingScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("failed to get taproot key: %s", err)
	}

	expectedScriptPubKey, err := common.P2TRScript(tapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get script pubkey: %s", err)
	}

	if !bytes.Equal(output.Script, expectedScriptPubKey) {
		return nil, fmt.Errorf("descriptor does not match script in transaction output")
	}

	if defaultVtxoScript, ok := boardingScript.(*tree.DefaultVtxoScript); ok {
		if !bytes.Equal(schnorr.SerializePubKey(defaultVtxoScript.Asp), schnorr.SerializePubKey(s.pubkey)) {
			return nil, fmt.Errorf("invalid boarding descriptor, ASP mismatch")
		}

		if defaultVtxoScript.ExitDelay != uint(s.boardingExitDelay) {
			return nil, fmt.Errorf("invalid boarding descriptor, timeout mismatch")
		}
	} else {
		return nil, fmt.Errorf("only default vtxo script is supported for boarding")
	}

	return &ports.BoardingInput{
		Amount: amount,
		Input:  input,
	}, nil
}

func (s *covenantService) ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver) error {
	// Check credentials
	payment, ok := s.paymentRequests.view(creds)
	if !ok {
		return fmt.Errorf("invalid credentials")
	}

	dustAmount, err := s.wallet.GetDustAmount(ctx)
	if err != nil {
		return err
	}

	for _, r := range receivers {
		if r.Amount <= dustAmount {
			return fmt.Errorf("receiver amount must be greater than dust amount: %d", dustAmount)
		}
	}

	if err := payment.AddReceivers(receivers); err != nil {
		return err
	}
	return s.paymentRequests.update(*payment)
}

func (s *covenantService) UpdatePaymentStatus(_ context.Context, id string) (domain.RoundEvent, error) {
	err := s.paymentRequests.updatePingTimestamp(id)
	if err != nil {
		if _, ok := err.(errPaymentNotFound); ok {
			return s.lastEvent, nil
		}

		return nil, err
	}

	return s.lastEvent, nil
}

func (s *covenantService) CompleteAsyncPayment(ctx context.Context, redeemTx string) error {
	return fmt.Errorf("unimplemented")
}

func (s *covenantService) CreateAsyncPayment(ctx context.Context, inputs []ports.Input, receivers []domain.Receiver) (string, error) {
	return "", fmt.Errorf("unimplemented")
}

func (s *covenantService) SignVtxos(ctx context.Context, forfeitTxs []string) error {
	return s.forfeitTxs.sign(forfeitTxs)
}

func (s *covenantService) SignRoundTx(ctx context.Context, signedRoundTx string) error {
	s.currentRoundLock.Lock()
	defer s.currentRoundLock.Unlock()

	combined, err := s.builder.VerifyAndCombinePartialTx(s.currentRound.UnsignedTx, signedRoundTx)
	if err != nil {
		return err
	}

	s.currentRound.UnsignedTx = combined
	return nil
}

func (s *covenantService) ListVtxos(ctx context.Context, pubkey *secp256k1.PublicKey) ([]domain.Vtxo, []domain.Vtxo, error) {
	pk := hex.EncodeToString(pubkey.SerializeCompressed())
	return s.repoManager.Vtxos().GetAllVtxos(ctx, pk)
}

func (s *covenantService) GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent {
	return s.eventsCh
}

func (s *covenantService) GetTransactionEventsChannel(ctx context.Context) <-chan TransactionEvent {
	return s.transactionEventsCh
}

func (s *covenantService) GetRoundByTxid(ctx context.Context, poolTxid string) (*domain.Round, error) {
	return s.repoManager.Rounds().GetRoundWithTxid(ctx, poolTxid)
}

func (s *covenantService) GetCurrentRound(ctx context.Context) (*domain.Round, error) {
	return domain.NewRoundFromEvents(s.currentRound.Events()), nil
}

func (s *covenantService) GetRoundById(ctx context.Context, id string) (*domain.Round, error) {
	return s.repoManager.Rounds().GetRoundWithId(ctx, id)
}

func (s *covenantService) GetInfo(ctx context.Context) (*ServiceInfo, error) {
	pubkey := hex.EncodeToString(s.pubkey.SerializeCompressed())

	dust, err := s.wallet.GetDustAmount(ctx)
	if err != nil {
		return nil, err
	}

	forfeitAddress, err := s.wallet.GetForfeitAddress(ctx)
	if err != nil {
		return nil, err
	}

	return &ServiceInfo{
		PubKey:              pubkey,
		RoundLifetime:       s.roundLifetime,
		UnilateralExitDelay: s.unilateralExitDelay,
		RoundInterval:       s.roundInterval,
		Network:             s.network.Name,
		Dust:                dust,
		BoardingDescriptorTemplate: fmt.Sprintf(
			descriptor.DefaultVtxoDescriptorTemplate,
			hex.EncodeToString(tree.UnspendableKey().SerializeCompressed()),
			"USER",
			hex.EncodeToString(schnorr.SerializePubKey(s.pubkey)),
			s.boardingExitDelay,
			"USER",
		),
		ForfeitAddress: forfeitAddress,
	}, nil
}

func (s *covenantService) RegisterCosignerPubkey(ctx context.Context, paymentId string, _ string) error {
	// if the user sends an ephemeral pubkey, something is going wrong client-side
	// we should delete the associated payment
	if err := s.paymentRequests.delete(paymentId); err != nil {
		log.WithError(err).Warn("failed to delete payment")
	}

	return ErrTreeSigningNotRequired
}

func (s *covenantService) RegisterCosignerNonces(context.Context, string, *secp256k1.PublicKey, string) error {
	return ErrTreeSigningNotRequired
}

func (s *covenantService) RegisterCosignerSignatures(context.Context, string, *secp256k1.PublicKey, string) error {
	return ErrTreeSigningNotRequired
}

func (s *covenantService) start() {
	s.startRound()
}

func (s *covenantService) startRound() {
	dustAmount, err := s.wallet.GetDustAmount(context.Background())
	if err != nil {
		log.WithError(err).Warn("failed to retrieve dust amount")
		return
	}
	round := domain.NewRound(dustAmount)
	//nolint:all
	round.StartRegistration()
	s.currentRound = round

	defer func() {
		time.Sleep(time.Duration(s.roundInterval/2) * time.Second)
		s.startFinalization()
	}()

	log.Debugf("started registration stage for new round: %s", round.Id)
}

func (s *covenantService) startFinalization() {
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
	payments, boardingInputs, _ := s.paymentRequests.pop(num)
	if _, err := round.RegisterPayments(payments); err != nil {
		round.Fail(fmt.Errorf("failed to register payments: %s", err))
		log.WithError(err).Warn("failed to register payments")
		return
	}

	sweptRounds, err := s.repoManager.Rounds().GetSweptRounds(ctx)
	if err != nil {
		round.Fail(fmt.Errorf("failed to retrieve swept rounds: %s", err))
		log.WithError(err).Warn("failed to retrieve swept rounds")
		return
	}

	unsignedPoolTx, tree, connectorAddress, err := s.builder.BuildRoundTx(s.pubkey, payments, boardingInputs, sweptRounds)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create pool tx: %s", err))
		log.WithError(err).Warn("failed to create pool tx")
		return
	}
	log.Debugf("pool tx created for round %s", round.Id)

	needForfeits := false
	for _, pay := range payments {
		if len(pay.Inputs) > 0 {
			needForfeits = true
			break
		}
	}

	var forfeitTxs, connectors []string

	minRelayFeeRate := s.wallet.MinRelayFeeRate(ctx)

	if needForfeits {
		connectors, forfeitTxs, err = s.builder.BuildForfeitTxs(unsignedPoolTx, payments, minRelayFeeRate)
		if err != nil {
			round.Fail(fmt.Errorf("failed to create connectors and forfeit txs: %s", err))
			log.WithError(err).Warn("failed to create connectors and forfeit txs")
			return
		}

		log.Debugf("forfeit transactions created for round %s", round.Id)

		if err := s.forfeitTxs.push(forfeitTxs); err != nil {
			round.Fail(fmt.Errorf("failed to cache forfeit txs: %s", err))
			log.WithError(err).Warn("failed to cache forfeit txs")
			return
		}
	}

	if _, err := round.StartFinalization(
		connectorAddress, connectors, tree, unsignedPoolTx,
	); err != nil {
		round.Fail(fmt.Errorf("failed to start finalization: %s", err))
		log.WithError(err).Warn("failed to start finalization")
		return
	}

	log.Debugf("started finalization stage for round: %s", round.Id)
}

func (s *covenantService) finalizeRound() {
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

	boardingInputs := make([]int, 0)
	roundTx, err := psetv2.NewPsetFromBase64(round.UnsignedTx)
	if err != nil {
		log.Debugf("failed to parse round tx: %s", round.UnsignedTx)
		changes = round.Fail(fmt.Errorf("failed to parse round tx: %s", err))
		log.WithError(err).Warn("failed to parse round tx")
		return
	}

	for i, in := range roundTx.Inputs {
		if len(in.TapLeafScript) > 0 {
			if len(in.TapScriptSig) == 0 {
				err = fmt.Errorf("missing tapscript spend sig for input %d", i)
				changes = round.Fail(err)
				log.WithError(err).Warn("missing boarding sig")
				return
			}

			boardingInputs = append(boardingInputs, i)
		}
	}

	signedRoundTx := round.UnsignedTx

	if len(boardingInputs) > 0 {
		signedRoundTx, err = s.wallet.SignTransactionTapscript(ctx, signedRoundTx, boardingInputs)
		if err != nil {
			changes = round.Fail(fmt.Errorf("failed to sign round tx: %s", err))
			log.WithError(err).Warn("failed to sign round tx")
			return
		}
	}

	signedRoundTx, err = s.wallet.SignTransaction(ctx, signedRoundTx, true)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to sign round tx: %s", err))
		log.WithError(err).Warn("failed to sign round tx")
		return
	}

	txid, err := s.wallet.BroadcastTransaction(ctx, signedRoundTx)
	if err != nil {
		log.Debugf("failed to broadcast round tx: %s", signedRoundTx)
		changes = round.Fail(fmt.Errorf("failed to broadcast pool tx: %s", err))
		log.WithError(err).Warn("failed to broadcast pool tx")
		return
	}

	changes, err = round.EndFinalization(forfeitTxs, txid)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to finalize round: %s", err))
		log.WithError(err).Warn("failed to finalize round")
		return
	}

	log.Debugf("finalized round %s with pool tx %s", round.Id, round.Txid)
}

func (s *covenantService) listenToScannerNotifications() {
	ctx := context.Background()
	chVtxos := s.scanner.GetNotificationChannel(ctx)

	mutx := &sync.Mutex{}
	for vtxoKeys := range chVtxos {
		go func(vtxoKeys map[string][]ports.VtxoWithValue) {
			vtxosRepo := s.repoManager.Vtxos()

			for _, keys := range vtxoKeys {
				for _, v := range keys {
					vtxos, err := vtxosRepo.GetVtxos(ctx, []domain.VtxoKey{v.VtxoKey})
					if err != nil {
						log.WithError(err).Warn("failed to retrieve vtxos, skipping...")
						continue
					}
					vtxo := vtxos[0]

					if !vtxo.Redeemed {
						go func() {
							if err := s.markAsRedeemed(ctx, vtxo); err != nil {
								log.WithError(err).Warnf("failed to mark vtxo %s:%d as redeemed", vtxo.Txid, vtxo.VOut)
							}
						}()
					}

					if vtxo.Spent {
						log.Infof("fraud detected on vtxo %s:%d", vtxo.Txid, vtxo.VOut)
						go func() {
							if err := s.reactToFraud(ctx, vtxo, mutx); err != nil {
								log.WithError(err).Warnf("failed to prevent fraud for vtxo %s:%d", vtxo.Txid, vtxo.VOut)
							}
						}()
					}
				}
			}
		}(vtxoKeys)
	}
}

func (s *covenantService) getNextConnector(
	ctx context.Context,
	round domain.Round,
) (string, uint32, error) {
	lastConnectorPtx, err := psetv2.NewPsetFromBase64(round.Connectors[len(round.Connectors)-1])
	if err != nil {
		return "", 0, err
	}

	var connectorAmount uint64
	for i := len(lastConnectorPtx.Outputs) - 1; i >= 0; i-- {
		o := lastConnectorPtx.Outputs[i]
		if len(o.Script) <= 0 {
			continue //	skip the fee output
		}

		connectorAmount = o.Value
		break
	}

	utxos, err := s.wallet.ListConnectorUtxos(ctx, round.ConnectorAddress)
	if err != nil {
		return "", 0, err
	}
	log.Debugf("found %d connector utxos, dust amount is %d", len(utxos), connectorAmount)

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
		if u.GetValue() == connectorAmount {
			return u.GetTxid(), u.GetIndex(), nil
		}
	}

	for _, u := range utxos {
		if u.GetValue() > connectorAmount {
			for _, b64 := range round.Connectors {
				partial, err := psetv2.NewPsetFromBase64(b64)
				if err != nil {
					return "", 0, err
				}

				for _, i := range partial.Inputs {
					txhash, err := chainhash.NewHash(i.PreviousTxid)
					if err != nil {
						return "", 0, err
					}

					if txhash.String() == u.GetTxid() && i.PreviousTxIndex == u.GetIndex() {
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

func (s *covenantService) reactToFraud(ctx context.Context, vtxo domain.Vtxo, mutx *sync.Mutex) error {
	round, err := s.repoManager.Rounds().GetRoundWithTxid(ctx, vtxo.SpentBy)
	if err != nil {
		return fmt.Errorf("failed to retrieve round: %s", err)
	}

	mutx.Lock()
	defer mutx.Unlock()

	connectorTxid, connectorVout, err := s.getNextConnector(ctx, *round)
	if err != nil {
		return fmt.Errorf("failed to retrieve next connector: %s", err)
	}

	forfeitTx, err := findForfeitTxLiquid(round.ForfeitTxs, connectorTxid, connectorVout, vtxo.Txid)
	if err != nil {
		return fmt.Errorf("failed to find forfeit tx: %s", err)
	}

	if err := s.wallet.LockConnectorUtxos(ctx, []ports.TxOutpoint{txOutpoint{connectorTxid, connectorVout}}); err != nil {
		return fmt.Errorf("failed to lock connector utxos: %s", err)
	}

	signedForfeitTx, err := s.wallet.SignTransaction(ctx, forfeitTx, false)
	if err != nil {
		return fmt.Errorf("failed to sign connector input in forfeit tx: %s", err)
	}

	signedForfeitTx, err = s.wallet.SignTransactionTapscript(ctx, signedForfeitTx, []int{1})
	if err != nil {
		return fmt.Errorf("failed to sign vtxo input in forfeit tx: %s", err)
	}

	forfeitTxHex, err := s.builder.FinalizeAndExtract(signedForfeitTx)
	if err != nil {
		return fmt.Errorf("failed to finalize forfeit tx: %s", err)
	}

	forfeitTxid, err := s.wallet.BroadcastTransaction(ctx, forfeitTxHex)
	if err != nil {
		return fmt.Errorf("failed to broadcast forfeit tx: %s", err)
	}

	log.Debugf("broadcasted forfeit tx %s", forfeitTxid)
	return nil
}

func (s *covenantService) markAsRedeemed(ctx context.Context, vtxo domain.Vtxo) error {
	if err := s.repoManager.Vtxos().RedeemVtxos(ctx, []domain.VtxoKey{vtxo.VtxoKey}); err != nil {
		return err
	}
	log.Debugf("vtxo %s redeemed", vtxo.Txid)
	return nil
}

func (s *covenantService) updateVtxoSet(round *domain.Round) {
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

	go func() {
		// nolint:all
		tx, _ := psetv2.NewPsetFromBase64(round.UnsignedTx)
		boardingInputs := make([]domain.VtxoKey, 0)
		for _, in := range tx.Inputs {
			if len(in.TapLeafScript) > 0 {
				boardingInputs = append(boardingInputs, domain.VtxoKey{
					Txid: elementsutil.TxIDFromBytes(in.PreviousTxid),
					VOut: in.PreviousTxIndex,
				})
			}
		}
		s.transactionEventsCh <- RoundTransactionEvent{
			RoundTxID:             round.Txid,
			SpentVtxos:            getSpentVtxos(round.Payments),
			SpendableVtxos:        s.getNewVtxos(round),
			ClaimedBoardingInputs: boardingInputs,
		}
	}()
}

func (s *covenantService) propagateEvents(round *domain.Round) {
	lastEvent := round.Events()[len(round.Events())-1]
	switch e := lastEvent.(type) {
	case domain.RoundFinalizationStarted:
		ev := domain.RoundFinalizationStarted{
			Id:              e.Id,
			CongestionTree:  e.CongestionTree,
			Connectors:      e.Connectors,
			RoundTx:         e.RoundTx,
			MinRelayFeeRate: int64(s.wallet.MinRelayFeeRate(context.Background())),
		}
		s.lastEvent = ev
		s.eventsCh <- ev
	case domain.RoundFinalized, domain.RoundFailed:
		s.lastEvent = e
		s.eventsCh <- e
	}
}

func (s *covenantService) scheduleSweepVtxosForRound(round *domain.Round) {
	// Schedule the sweeping procedure only for completed round.
	if !round.IsEnded() {
		return
	}

	expirationTime := s.sweeper.scheduler.AddNow(s.roundLifetime)

	if err := s.sweeper.schedule(
		expirationTime, round.Txid, round.CongestionTree,
	); err != nil {
		log.WithError(err).Warn("failed to schedule sweep tx")
	}
}

func (s *covenantService) getNewVtxos(round *domain.Round) []domain.Vtxo {
	if len(round.CongestionTree) <= 0 {
		return nil
	}

	leaves := round.CongestionTree.Leaves()
	vtxos := make([]domain.Vtxo, 0)
	for _, node := range leaves {
		tx, _ := psetv2.NewPsetFromBase64(node.Tx)
		for i, out := range tx.Outputs {
			if len(out.Script) <= 0 {
				continue // skip fee outputs
			}

			desc := ""
			found := false

			for _, p := range round.Payments {
				if found {
					break
				}

				for _, r := range p.Receivers {
					if r.IsOnchain() {
						continue
					}

					vtxoScript, err := tree.ParseVtxoScript(r.Descriptor)
					if err != nil {
						log.WithError(err).Warn("failed to parse vtxo descriptor")
						continue
					}

					tapKey, _, err := vtxoScript.TapTree()
					if err != nil {
						log.WithError(err).Warn("failed to compute vtxo tap key")
						continue
					}

					script, err := common.P2TRScript(tapKey)
					if err != nil {
						log.WithError(err).Warn("failed to create vtxo scriptpubkey")
						continue
					}

					if bytes.Equal(script, out.Script) {
						found = true
						desc = r.Descriptor
						break
					}
				}
			}

			if found {
				vtxos = append(vtxos, domain.Vtxo{
					VtxoKey:   domain.VtxoKey{Txid: node.Txid, VOut: uint32(i)},
					Receiver:  domain.Receiver{Descriptor: desc, Amount: uint64(out.Value)},
					RoundTxid: round.Txid,
				})
				break
			}
		}
	}
	return vtxos
}

func (s *covenantService) startWatchingVtxos(vtxos []domain.Vtxo) error {
	scripts, err := s.extractVtxosScripts(vtxos)
	if err != nil {
		return err
	}

	return s.scanner.WatchScripts(context.Background(), scripts)
}

func (s *covenantService) stopWatchingVtxos(vtxos []domain.Vtxo) {
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

func (s *covenantService) restoreWatchingVtxos() error {
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

func (s *covenantService) extractVtxosScripts(vtxos []domain.Vtxo) ([]string, error) {
	indexedScripts := make(map[string]struct{})
	for _, vtxo := range vtxos {
		vtxoScript, err := tree.ParseVtxoScript(vtxo.Receiver.Descriptor)
		if err != nil {
			return nil, err
		}

		tapKey, _, err := vtxoScript.TapTree()
		if err != nil {
			return nil, err
		}

		script, err := common.P2TRScript(tapKey)
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

func (s *covenantService) saveEvents(
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

func (s *covenantService) onchainNetwork() *network.Network {
	switch s.network {
	case common.Liquid:
		return &network.Liquid
	case common.LiquidTestNet:
		return &network.Testnet
	case common.LiquidRegTest:
		return &network.Regtest
	default:
		return nil
	}
}

func findForfeitTxLiquid(
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
