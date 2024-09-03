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
	"github.com/ark-network/ark/common/descriptor"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/elementsutil"
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
	minRelayFee         uint64

	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder
	scanner     ports.BlockchainScanner
	sweeper     *sweeper

	paymentRequests *paymentsMap
	forfeitTxs      *forfeitTxsMap

	eventsCh chan domain.RoundEvent

	currentRoundLock sync.Mutex
	currentRound     *domain.Round
	lastEvent        domain.RoundEvent
}

func NewCovenantService(
	network common.Network,
	roundInterval, roundLifetime, unilateralExitDelay, boardingExitDelay int64, minRelayFee uint64,
	walletSvc ports.WalletService, repoManager ports.RepoManager,
	builder ports.TxBuilder, scanner ports.BlockchainScanner,
	scheduler ports.SchedulerService,
) (Service, error) {
	eventsCh := make(chan domain.RoundEvent)
	paymentRequests := newPaymentsMap()

	forfeitTxs := newForfeitTxsMap(builder)
	pubkey, err := walletSvc.GetPubkey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pubkey: %s", err)
	}

	sweeper := newSweeper(walletSvc, repoManager, builder, scheduler)

	svc := &covenantService{
		network, pubkey,
		roundLifetime, roundInterval, unilateralExitDelay, boardingExitDelay, minRelayFee,
		walletSvc, repoManager, builder, scanner, sweeper,
		paymentRequests, forfeitTxs, eventsCh, sync.Mutex{}, nil, nil,
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

func (s *covenantService) GetBoardingAddress(ctx context.Context, userPubkey *secp256k1.PublicKey) (string, error) {
	addr, _, err := s.builder.GetBoardingScript(userPubkey, s.pubkey)
	if err != nil {
		return "", err
	}
	return addr, nil
}

func (s *covenantService) SpendVtxos(ctx context.Context, inputs []Input) (string, error) {
	vtxosInputs := make([]domain.VtxoKey, 0)
	boardingInputs := make([]Input, 0)

	for _, in := range inputs {
		if in.IsVtxo() {
			vtxosInputs = append(vtxosInputs, in.VtxoKey())
			continue
		}
		boardingInputs = append(boardingInputs, in)
	}

	vtxos := make([]domain.Vtxo, 0)

	if len(vtxosInputs) > 0 {
		var err error
		vtxos, err = s.repoManager.Vtxos().GetVtxos(ctx, vtxosInputs)
		if err != nil {
			return "", err
		}
		for _, v := range vtxos {
			if v.Spent {
				return "", fmt.Errorf("input %s:%d already spent", v.Txid, v.VOut)
			}

			if v.Redeemed {
				return "", fmt.Errorf("input %s:%d already redeemed", v.Txid, v.VOut)
			}

			if v.Spent {
				return "", fmt.Errorf("input %s:%d already spent", v.Txid, v.VOut)
			}
		}
	}

	boardingTxs := make(map[string]string, 0) // txid -> txhex
	now := time.Now().Unix()

	for _, in := range boardingInputs {
		if _, ok := boardingTxs[in.Txid]; !ok {
			txhex, err := s.wallet.GetTransaction(ctx, in.Txid)
			if err != nil {
				return "", fmt.Errorf("failed to get tx %s: %s", in.Txid, err)
			}

			confirmed, blocktime, err := s.wallet.IsTransactionConfirmed(ctx, in.Txid)
			if err != nil {
				return "", fmt.Errorf("failed to check tx %s: %s", in.Txid, err)
			}

			if !confirmed {
				return "", fmt.Errorf("tx %s not confirmed", in.Txid)
			}

			if blocktime+int64(s.boardingExitDelay) < now {
				return "", fmt.Errorf("tx %s expired", in.Txid)
			}

			boardingTxs[in.Txid] = txhex
		}
	}

	utxos := make([]ports.BoardingInput, 0, len(boardingInputs))

	for _, in := range boardingInputs {
		desc, err := in.GetDescriptor()
		if err != nil {
			log.WithError(err).Debugf("failed to parse boarding input descriptor")
			return "", fmt.Errorf("failed to parse descriptor %s for input %s:%d", in.Descriptor, in.Txid, in.Index)
		}
		input, err := s.newBoardingInput(boardingTxs[in.Txid], in.Index, *desc)
		if err != nil {
			log.WithError(err).Debugf("failed to create boarding input")
			return "", fmt.Errorf("input %s:%d is not a valid boarding input", in.Txid, in.Index)
		}

		utxos = append(utxos, input)
	}

	payment, err := domain.NewPayment(vtxos)
	if err != nil {
		return "", err
	}
	if err := s.paymentRequests.push(*payment, utxos); err != nil {
		return "", err
	}
	return payment.Id, nil
}

func (s *covenantService) newBoardingInput(
	txhex string, vout uint32, desc descriptor.TaprootDescriptor,
) (ports.BoardingInput, error) {
	tx, err := transaction.NewTxFromHex(txhex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tx: %s", err)
	}

	if len(tx.Outputs) <= int(vout) {
		return nil, fmt.Errorf("output not found")
	}

	out := tx.Outputs[vout]
	script := out.Script

	if len(out.RangeProof) > 0 || len(out.SurjectionProof) > 0 {
		return nil, fmt.Errorf("output is confidential")
	}

	scriptFromDescriptor, err := tree.ComputeOutputScript(desc)
	if err != nil {
		return nil, fmt.Errorf("failed to compute output script: %s", err)
	}

	if !bytes.Equal(script, scriptFromDescriptor) {
		return nil, fmt.Errorf("descriptor does not match script in transaction output")
	}

	pubkey, timeout, err := descriptor.ParseBoardingDescriptor(desc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse boarding descriptor: %s", err)
	}

	if timeout != uint(s.boardingExitDelay) {
		return nil, fmt.Errorf("invalid boarding descriptor, timeout mismatch")
	}

	_, expectedScript, err := s.builder.GetBoardingScript(pubkey, s.pubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute boarding script: %s", err)
	}

	if !bytes.Equal(script, expectedScript) {
		return nil, fmt.Errorf("output script mismatch expected script")
	}

	value, err := elementsutil.ValueFromBytes(out.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to parse value: %s", err)
	}

	return &boardingInput{
		txId:           tx.TxHash(),
		vout:           vout,
		boardingPubKey: pubkey,
		amount:         value,
	}, nil
}

func (s *covenantService) ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver) error {
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

func (s *covenantService) CompleteAsyncPayment(ctx context.Context, redeemTx string, unconditionalForfeitTxs []string) error {
	return fmt.Errorf("unimplemented")
}

func (s *covenantService) CreateAsyncPayment(ctx context.Context, inputs []domain.VtxoKey, receivers []domain.Receiver) (string, []string, error) {
	return "", nil, fmt.Errorf("unimplemented")
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

	return &ServiceInfo{
		PubKey:              pubkey,
		RoundLifetime:       s.roundLifetime,
		UnilateralExitDelay: s.unilateralExitDelay,
		RoundInterval:       s.roundInterval,
		Network:             s.network.Name,
		MinRelayFee:         int64(s.minRelayFee),
		BoardingDescriptorTemplate: fmt.Sprintf(
			descriptor.BoardingDescriptorTemplate,
			hex.EncodeToString(tree.UnspendableKey().SerializeCompressed()),
			hex.EncodeToString(schnorr.SerializePubKey(s.pubkey)),
			"USER",
			s.boardingExitDelay,
			"USER",
		),
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
	round := domain.NewRound(dustAmount)
	//nolint:all
	round.StartRegistration()
	s.lastEvent = nil
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

	unsignedPoolTx, tree, connectorAddress, err := s.builder.BuildPoolTx(s.pubkey, payments, boardingInputs, s.minRelayFee, sweptRounds)
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

	if needForfeits {
		connectors, forfeitTxs, err = s.builder.BuildForfeitTxs(s.pubkey, unsignedPoolTx, payments, s.minRelayFee)
		if err != nil {
			round.Fail(fmt.Errorf("failed to create connectors and forfeit txs: %s", err))
			log.WithError(err).Warn("failed to create connectors and forfeit txs")
			return
		}

		log.Debugf("forfeit transactions created for round %s", round.Id)
	}

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

				if err := s.repoManager.Vtxos().RedeemVtxos(ctx, []domain.VtxoKey{vtxo.VtxoKey}); err != nil {
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

				forfeitTx, err := findForfeitTxLiquid(round.ForfeitTxs, connectorTxid, connectorVout, vtxo.Txid)
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

func (s *covenantService) getNextConnector(
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
				partial, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
				if err != nil {
					return "", 0, err
				}

				for _, i := range partial.UnsignedTx.TxIn {
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
}

func (s *covenantService) propagateEvents(round *domain.Round) {
	lastEvent := round.Events()[len(round.Events())-1]
	switch e := lastEvent.(type) {
	case domain.RoundFinalizationStarted:
		forfeitTxs := s.forfeitTxs.view()
		ev := domain.RoundFinalizationStarted{
			Id:                 e.Id,
			CongestionTree:     e.CongestionTree,
			Connectors:         e.Connectors,
			PoolTx:             e.PoolTx,
			UnsignedForfeitTxs: forfeitTxs,
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

	expirationTimestamp := time.Now().Add(
		time.Duration(s.roundLifetime+30) * time.Second,
	)

	if err := s.sweeper.schedule(
		expirationTimestamp.Unix(), round.Txid, round.CongestionTree,
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
