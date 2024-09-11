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
	"github.com/ark-network/ark/common/descriptor"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
)

type covenantlessService struct {
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

	eventsCh chan domain.RoundEvent

	// cached data for the current round
	lastEvent           domain.RoundEvent
	currentRoundLock    sync.Mutex
	currentRound        *domain.Round
	treeSigningSessions map[string]*musigSigningSession
	asyncPaymentsCache  map[string]struct { // redeem txid -> receivers
		receivers []domain.Receiver
		expireAt  int64
	}
}

func NewCovenantlessService(
	network common.Network,
	roundInterval, roundLifetime, unilateralExitDelay, boardingExitDelay int64,
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
	asyncPaymentsCache := make(map[string]struct {
		receivers []domain.Receiver
		expireAt  int64
	})

	svc := &covenantlessService{
		network:             network,
		pubkey:              pubkey,
		roundLifetime:       roundLifetime,
		roundInterval:       roundInterval,
		unilateralExitDelay: unilateralExitDelay,
		wallet:              walletSvc,
		repoManager:         repoManager,
		builder:             builder,
		scanner:             scanner,
		sweeper:             sweeper,
		paymentRequests:     paymentRequests,
		forfeitTxs:          forfeitTxs,
		eventsCh:            eventsCh,
		currentRoundLock:    sync.Mutex{},
		asyncPaymentsCache:  asyncPaymentsCache,
		treeSigningSessions: make(map[string]*musigSigningSession),
		boardingExitDelay:   boardingExitDelay,
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
}

func (s *covenantlessService) CompleteAsyncPayment(
	ctx context.Context, redeemTx string, unconditionalForfeitTxs []string,
) error {
	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(redeemTx), true)
	if err != nil {
		return fmt.Errorf("failed to parse redeem tx: %s", err)
	}
	redeemTxid := redeemPtx.UnsignedTx.TxID()

	asyncPayData, ok := s.asyncPaymentsCache[redeemTxid]
	if !ok {
		return fmt.Errorf("async payment not found")
	}

	txs := append([]string{redeemTx}, unconditionalForfeitTxs...)
	vtxoRepo := s.repoManager.Vtxos()

	for _, tx := range txs {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		if err != nil {
			return fmt.Errorf("failed to parse tx: %s", err)
		}

		for inputIndex, input := range ptx.Inputs {
			if input.WitnessUtxo == nil {
				return fmt.Errorf("missing witness utxo")
			}

			if len(input.TaprootLeafScript) == 0 {
				return fmt.Errorf("missing tapscript leaf")
			}

			if len(input.TaprootScriptSpendSig) == 0 {
				return fmt.Errorf("missing tapscript spend sig")
			}

			vtxoOutpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint

			// verify that the vtxo is spendable

			vtxo, err := vtxoRepo.GetVtxos(ctx, []domain.VtxoKey{{Txid: vtxoOutpoint.Hash.String(), VOut: vtxoOutpoint.Index}})
			if err != nil {
				return fmt.Errorf("failed to get vtxo: %s", err)
			}

			if len(vtxo) == 0 {
				return fmt.Errorf("vtxo not found")
			}

			if vtxo[0].Spent {
				return fmt.Errorf("vtxo already spent")
			}

			if vtxo[0].Redeemed {
				return fmt.Errorf("vtxo already redeemed")
			}

			if vtxo[0].Swept {
				return fmt.Errorf("vtxo already swept")
			}

			// verify that the user signs the tx using the right public key

			vtxoPublicKey, err := hex.DecodeString(vtxo[0].Pubkey)
			if err != nil {
				return fmt.Errorf("failed to decode pubkey: %s", err)
			}

			pubkey, err := secp256k1.ParsePubKey(vtxoPublicKey)
			if err != nil {
				return fmt.Errorf("failed to parse pubkey: %s", err)
			}

			xonlyPubkey := schnorr.SerializePubKey(pubkey)

			// find signature belonging to the pubkey
			found := false

			for _, sig := range input.TaprootScriptSpendSig {
				if bytes.Equal(sig.XOnlyPubKey, xonlyPubkey) {
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("signature not found for pubkey")
			}

			// verify witness utxo

			pkscript, err := s.builder.GetVtxoScript(pubkey, s.pubkey)
			if err != nil {
				return fmt.Errorf("failed to get vtxo script: %s", err)
			}

			if !bytes.Equal(input.WitnessUtxo.PkScript, pkscript) {
				return fmt.Errorf("witness utxo script mismatch")
			}

			if input.WitnessUtxo.Value != int64(vtxo[0].Amount) {
				return fmt.Errorf("witness utxo value mismatch")
			}
		}

		// verify the tapscript signatures
		if valid, _, err := s.builder.VerifyTapscriptPartialSigs(tx); err != nil || !valid {
			return fmt.Errorf("invalid tx signature: %s", err)
		}
	}

	spentVtxos := make([]domain.VtxoKey, 0, len(unconditionalForfeitTxs))
	for _, in := range redeemPtx.UnsignedTx.TxIn {
		spentVtxos = append(spentVtxos, domain.VtxoKey{
			Txid: in.PreviousOutPoint.Hash.String(),
			VOut: in.PreviousOutPoint.Index,
		})
	}

	vtxos := make([]domain.Vtxo, 0, len(asyncPayData.receivers))

	for outIndex, out := range redeemPtx.UnsignedTx.TxOut {
		vtxos = append(vtxos, domain.Vtxo{
			VtxoKey: domain.VtxoKey{
				Txid: redeemTxid,
				VOut: uint32(outIndex),
			},
			Receiver: domain.Receiver{
				Pubkey: asyncPayData.receivers[outIndex].Pubkey,
				Amount: uint64(out.Value),
			},
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
	if err := s.startWatchingVtxos(vtxos); err != nil {
		log.WithError(err).Warn(
			"failed to start watching vtxos",
		)
	}
	log.Debugf("started watching %d vtxos", len(vtxos))

	if err := s.repoManager.Vtxos().SpendVtxos(ctx, spentVtxos, redeemTxid); err != nil {
		return fmt.Errorf("failed to spend vtxo: %s", err)
	}
	log.Infof("spent %d vtxos", len(spentVtxos))

	delete(s.asyncPaymentsCache, redeemTxid)

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
		vtxos, s.pubkey, receivers,
	)
	if err != nil {
		return "", nil, fmt.Errorf("failed to build async payment txs: %s", err)
	}

	redeemTx, err := psbt.NewFromRawBytes(strings.NewReader(res.RedeemTx), true)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse redeem tx: %s", err)
	}

	s.asyncPaymentsCache[redeemTx.UnsignedTx.TxID()] = struct {
		receivers []domain.Receiver
		expireAt  int64
	}{
		receivers: receivers,
		expireAt:  expiration,
	}

	return res.RedeemTx, res.UnconditionalForfeitTxs, nil
}

func (s *covenantlessService) SpendVtxos(ctx context.Context, inputs []Input) (string, error) {
	vtxosInputs := make([]domain.VtxoKey, 0)
	boardingInputs := make([]Input, 0)

	for _, input := range inputs {
		if input.IsVtxo() {
			vtxosInputs = append(vtxosInputs, input.VtxoKey())
			continue
		}

		boardingInputs = append(boardingInputs, input)
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
			// check if the tx exists and is confirmed
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

			// if the exit path is available, forbid registering the boarding utxo
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

func (s *covenantlessService) newBoardingInput(txhex string, vout uint32, desc descriptor.TaprootDescriptor) (ports.BoardingInput, error) {
	var tx wire.MsgTx

	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
		return nil, fmt.Errorf("failed to deserialize tx: %s", err)
	}

	if len(tx.TxOut) <= int(vout) {
		return nil, fmt.Errorf("output not found")
	}

	out := tx.TxOut[vout]
	script := out.PkScript

	scriptFromDescriptor, err := bitcointree.ComputeOutputScript(desc)
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
		return nil, fmt.Errorf("failed to get boarding script: %s", err)
	}

	if !bytes.Equal(script, expectedScript) {
		return nil, fmt.Errorf("invalid boarding input output script")
	}

	return &boardingInput{
		txId:           tx.TxHash(),
		vout:           vout,
		boardingPubKey: pubkey,
		amount:         uint64(out.Value),
	}, nil
}

func (s *covenantlessService) ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver) error {
	// Check credentials
	payment, ok := s.paymentRequests.view(creds)
	if !ok {
		return fmt.Errorf("invalid credentials")
	}

	dustAmount, err := s.wallet.GetDustAmount(ctx)
	if err != nil {
		return fmt.Errorf("unable to verify receiver amount, failed to get dust: %s", err)
	}

	for _, rcv := range receivers {
		if rcv.Amount <= dustAmount {
			return fmt.Errorf("receiver amount must be greater than dust amount %d", dustAmount)
		}
	}

	if err := payment.AddReceivers(receivers); err != nil {
		return err
	}
	return s.paymentRequests.update(*payment)
}

func (s *covenantlessService) UpdatePaymentStatus(_ context.Context, id string) (domain.RoundEvent, error) {
	err := s.paymentRequests.updatePingTimestamp(id)
	if err != nil {
		if _, ok := err.(errPaymentNotFound); ok {
			return s.lastEvent, nil
		}

		return nil, err
	}

	return s.lastEvent, nil
}

func (s *covenantlessService) SignVtxos(ctx context.Context, forfeitTxs []string) error {
	return s.forfeitTxs.sign(forfeitTxs)
}

func (s *covenantlessService) SignRoundTx(ctx context.Context, signedRoundTx string) error {
	s.currentRoundLock.Lock()
	defer s.currentRoundLock.Unlock()

	combined, err := s.builder.VerifyAndCombinePartialTx(s.currentRound.UnsignedTx, signedRoundTx)
	if err != nil {
		return fmt.Errorf("failed to verify and combine partial tx: %s", err)
	}

	s.currentRound.UnsignedTx = combined
	return nil
}

func (s *covenantlessService) ListVtxos(ctx context.Context, pubkey *secp256k1.PublicKey) ([]domain.Vtxo, []domain.Vtxo, error) {
	pk := hex.EncodeToString(pubkey.SerializeCompressed())
	return s.repoManager.Vtxos().GetAllVtxos(ctx, pk)
}

func (s *covenantlessService) GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent {
	return s.eventsCh
}

func (s *covenantlessService) GetRoundByTxid(ctx context.Context, roundTxid string) (*domain.Round, error) {
	return s.repoManager.Rounds().GetRoundWithTxid(ctx, roundTxid)
}

func (s *covenantlessService) GetRoundById(ctx context.Context, id string) (*domain.Round, error) {
	return s.repoManager.Rounds().GetRoundWithId(ctx, id)
}

func (s *covenantlessService) GetCurrentRound(ctx context.Context) (*domain.Round, error) {
	return domain.NewRoundFromEvents(s.currentRound.Events()), nil
}

func (s *covenantlessService) GetInfo(ctx context.Context) (*ServiceInfo, error) {
	pubkey := hex.EncodeToString(s.pubkey.SerializeCompressed())

	dust, err := s.wallet.GetDustAmount(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get dust amount: %s", err)
	}

	return &ServiceInfo{
		PubKey:              pubkey,
		RoundLifetime:       s.roundLifetime,
		UnilateralExitDelay: s.unilateralExitDelay,
		RoundInterval:       s.roundInterval,
		Network:             s.network.Name,
		Dust:                dust,
		BoardingDescriptorTemplate: fmt.Sprintf(
			descriptor.BoardingDescriptorTemplate,
			hex.EncodeToString(bitcointree.UnspendableKey().SerializeCompressed()),
			hex.EncodeToString(schnorr.SerializePubKey(s.pubkey)),
			"USER",
			s.boardingExitDelay,
			"USER",
		),
	}, nil
}

func (s *covenantlessService) GetBoardingAddress(
	ctx context.Context, userPubkey *secp256k1.PublicKey,
) (string, error) {
	addr, _, err := s.builder.GetBoardingScript(userPubkey, s.pubkey)
	if err != nil {
		return "", fmt.Errorf("failed to compute boarding script: %s", err)
	}

	return addr, nil
}

func (s *covenantlessService) RegisterCosignerPubkey(ctx context.Context, paymentId string, pubkey string) error {
	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		return fmt.Errorf("failed to decode hex pubkey: %s", err)
	}

	ephemeralPublicKey, err := secp256k1.ParsePubKey(pubkeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse pubkey: %s", err)
	}

	return s.paymentRequests.pushEphemeralKey(paymentId, ephemeralPublicKey)
}

func (s *covenantlessService) RegisterCosignerNonces(
	ctx context.Context, roundID string, pubkey *secp256k1.PublicKey, encodedNonces string,
) error {
	session, ok := s.treeSigningSessions[roundID]
	if !ok {
		return fmt.Errorf(`signing session not found for round "%s"`, roundID)
	}

	nonces, err := bitcointree.DecodeNonces(hex.NewDecoder(strings.NewReader(encodedNonces)))
	if err != nil {
		return fmt.Errorf("failed to decode nonces: %s", err)
	}

	session.lock.Lock()
	defer session.lock.Unlock()

	if _, ok := session.nonces[pubkey]; ok {
		return nil // skip if we already have nonces for this pubkey
	}

	session.nonces[pubkey] = nonces

	if len(session.nonces) == session.nbCosigners-1 { // exclude the ASP
		session.nonceDoneC <- struct{}{}
	}

	return nil
}

func (s *covenantlessService) RegisterCosignerSignatures(
	ctx context.Context, roundID string, pubkey *secp256k1.PublicKey, encodedSignatures string,
) error {
	session, ok := s.treeSigningSessions[roundID]
	if !ok {
		return fmt.Errorf(`signing session not found for round "%s"`, roundID)
	}

	signatures, err := bitcointree.DecodeSignatures(hex.NewDecoder(strings.NewReader(encodedSignatures)))
	if err != nil {
		return fmt.Errorf("failed to decode signatures: %s", err)
	}

	session.lock.Lock()
	defer session.lock.Unlock()

	if _, ok := session.signatures[pubkey]; ok {
		return nil // skip if we already have signatures for this pubkey
	}

	session.signatures[pubkey] = signatures

	if len(session.signatures) == session.nbCosigners-1 { // exclude the ASP
		session.sigDoneC <- struct{}{}
	}

	return nil
}

func (s *covenantlessService) start() {
	s.startRound()
}

func (s *covenantlessService) startRound() {
	dustAmount, err := s.wallet.GetDustAmount(context.Background())
	if err != nil {
		log.WithError(err).Warn("failed to get dust amount")
		return
	}

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

func (s *covenantlessService) startFinalization() {
	ctx := context.Background()
	round := s.currentRound

	roundRemainingDuration := time.Duration(s.roundInterval/2-1) * time.Second
	thirdOfRemainingDuration := time.Duration(roundRemainingDuration / 3)

	var roundAborted bool
	defer func() {
		delete(s.treeSigningSessions, round.Id)
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
		time.Sleep(thirdOfRemainingDuration)
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
	payments, boardingInputs, cosigners := s.paymentRequests.pop(num)
	if len(payments) > len(cosigners) {
		err := fmt.Errorf("missing ephemeral key for payments")
		round.Fail(fmt.Errorf("round aborted: %s", err))
		log.WithError(err).Debugf("round %s aborted", round.Id)
		return
	}

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

	ephemeralKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		round.Fail(fmt.Errorf("failed to generate ephemeral key: %s", err))
		log.WithError(err).Warn("failed to generate ephemeral key")
		return
	}

	cosigners = append(cosigners, ephemeralKey.PubKey())

	unsignedRoundTx, tree, connectorAddress, err := s.builder.BuildPoolTx(s.pubkey, payments, boardingInputs, sweptRounds, cosigners...)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create pool tx: %s", err))
		log.WithError(err).Warn("failed to create pool tx")
		return
	}
	log.Debugf("pool tx created for round %s", round.Id)

	if len(tree) > 0 {
		log.Debugf("signing congestion tree for round %s", round.Id)

		signingSession := newMusigSigningSession(len(cosigners))
		s.treeSigningSessions[round.Id] = signingSession

		log.Debugf("signing session created for round %s", round.Id)

		s.currentRound.UnsignedTx = unsignedRoundTx
		// send back the unsigned tree & all cosigners pubkeys
		s.propagateRoundSigningStartedEvent(tree, cosigners)

		sweepClosure := bitcointree.CSVSigClosure{
			Pubkey:  s.pubkey,
			Seconds: uint(s.roundLifetime),
		}

		sweepTapLeaf, err := sweepClosure.Leaf()
		if err != nil {
			return
		}

		unsignedPsbt, err := psbt.NewFromRawBytes(strings.NewReader(unsignedRoundTx), true)
		if err != nil {
			round.Fail(fmt.Errorf("failed to parse round tx: %s", err))
			log.WithError(err).Warn("failed to parse round tx")
			return
		}

		sharedOutputAmount := unsignedPsbt.UnsignedTx.TxOut[0].Value

		sweepTapTree := txscript.AssembleTaprootScriptTree(*sweepTapLeaf)
		root := sweepTapTree.RootNode.TapHash()

		coordinator, err := bitcointree.NewTreeCoordinatorSession(sharedOutputAmount, tree, root.CloneBytes(), cosigners)
		if err != nil {
			round.Fail(fmt.Errorf("failed to create tree coordinator: %s", err))
			log.WithError(err).Warn("failed to create tree coordinator")
			return
		}

		aspSignerSession := bitcointree.NewTreeSignerSession(
			ephemeralKey, sharedOutputAmount, tree, root.CloneBytes(),
		)

		nonces, err := aspSignerSession.GetNonces()
		if err != nil {
			round.Fail(fmt.Errorf("failed to get nonces: %s", err))
			log.WithError(err).Warn("failed to get nonces")
			return
		}

		if err := coordinator.AddNonce(ephemeralKey.PubKey(), nonces); err != nil {
			round.Fail(fmt.Errorf("failed to add nonce: %s", err))
			log.WithError(err).Warn("failed to add nonce")
			return
		}

		noncesTimer := time.NewTimer(thirdOfRemainingDuration)

		select {
		case <-noncesTimer.C:
			round.Fail(fmt.Errorf("musig2 signing session timed out (nonce collection)"))
			log.Warn("musig2 signing session timed out (nonce collection)")
			return
		case <-signingSession.nonceDoneC:
			noncesTimer.Stop()
			for pubkey, nonce := range signingSession.nonces {
				if err := coordinator.AddNonce(pubkey, nonce); err != nil {
					round.Fail(fmt.Errorf("failed to add nonce: %s", err))
					log.WithError(err).Warn("failed to add nonce")
					return
				}
			}
		}

		log.Debugf("nonces collected for round %s", round.Id)

		aggragatedNonces, err := coordinator.AggregateNonces()
		if err != nil {
			round.Fail(fmt.Errorf("failed to aggregate nonces: %s", err))
			log.WithError(err).Warn("failed to aggregate nonces")
			return
		}

		log.Debugf("nonces aggregated for round %s", round.Id)

		s.propagateRoundSigningNoncesGeneratedEvent(aggragatedNonces)

		if err := aspSignerSession.SetKeys(cosigners); err != nil {
			round.Fail(fmt.Errorf("failed to set keys: %s", err))
			log.WithError(err).Warn("failed to set keys")
			return
		}

		if err := aspSignerSession.SetAggregatedNonces(aggragatedNonces); err != nil {
			round.Fail(fmt.Errorf("failed to set aggregated nonces: %s", err))
			log.WithError(err).Warn("failed to set aggregated nonces")
			return
		}

		// sign the tree as ASP
		aspTreeSigs, err := aspSignerSession.Sign()
		if err != nil {
			round.Fail(fmt.Errorf("failed to sign tree: %s", err))
			log.WithError(err).Warn("failed to sign tree")
			return
		}

		if err := coordinator.AddSig(ephemeralKey.PubKey(), aspTreeSigs); err != nil {
			round.Fail(fmt.Errorf("failed to add signature: %s", err))
			log.WithError(err).Warn("failed to add signature")
			return
		}

		log.Debugf("ASP tree signed for round %s", round.Id)

		signaturesTimer := time.NewTimer(thirdOfRemainingDuration)

		log.Debugf("waiting for cosigners to sign the tree")

		select {
		case <-signaturesTimer.C:
			round.Fail(fmt.Errorf("musig2 signing session timed out (signatures)"))
			log.Warn("musig2 signing session timed out (signatures)")
			return
		case <-signingSession.sigDoneC:
			signaturesTimer.Stop()
			for pubkey, sig := range signingSession.signatures {
				if err := coordinator.AddSig(pubkey, sig); err != nil {
					round.Fail(fmt.Errorf("failed to add signature: %s", err))
					log.WithError(err).Warn("failed to add signature")
					return
				}
			}
		}

		log.Debugf("signatures collected for round %s", round.Id)

		signedTree, err := coordinator.SignTree()
		if err != nil {
			round.Fail(fmt.Errorf("failed to aggregate tree signatures: %s", err))
			log.WithError(err).Warn("failed to aggregate tree signatures")
			return
		}

		log.Debugf("congestion tree signed for round %s", round.Id)

		tree = signedTree
	}

	needForfeits := false
	for _, pay := range payments {
		if len(pay.Inputs) > 0 {
			needForfeits = true
			break
		}
	}

	var forfeitTxs, connectors []string

	if needForfeits {
		connectors, forfeitTxs, err = s.builder.BuildForfeitTxs(s.pubkey, unsignedRoundTx, payments)
		if err != nil {
			round.Fail(fmt.Errorf("failed to create connectors and forfeit txs: %s", err))
			log.WithError(err).Warn("failed to create connectors and forfeit txs")
			return
		}
		log.Debugf("forfeit transactions created for round %s", round.Id)
	}

	if _, err := round.StartFinalization(
		connectorAddress, connectors, tree, unsignedRoundTx,
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
	ev := RoundSigningStarted{
		Id:               s.currentRound.Id,
		UnsignedVtxoTree: unsignedCongestionTree,
		Cosigners:        cosigners,
		UnsignedRoundTx:  s.currentRound.UnsignedTx,
	}

	s.lastEvent = ev
	s.eventsCh <- ev
}

func (s *covenantlessService) propagateRoundSigningNoncesGeneratedEvent(combinedNonces bitcointree.TreeNonces) {
	ev := RoundSigningNoncesGenerated{
		Id:     s.currentRound.Id,
		Nonces: combinedNonces,
	}

	s.lastEvent = ev
	s.eventsCh <- ev
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

	boardingInputs := make([]int, 0)
	roundTx, err := psbt.NewFromRawBytes(strings.NewReader(round.UnsignedTx), true)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to parse round tx: %s", err))
		log.WithError(err).Warn("failed to parse round tx")
		return
	}

	for i, in := range roundTx.Inputs {
		if len(in.TaprootLeafScript) > 0 {
			if len(in.TaprootScriptSpendSig) == 0 {
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

func (s *covenantlessService) listenToScannerNotifications() {
	ctx := context.Background()
	chVtxos := s.scanner.GetNotificationChannel(ctx)

	mutx := &sync.Mutex{}
	for vtxoKeys := range chVtxos {
		go func(vtxoKeys map[string][]ports.VtxoWithValue) {
			vtxosRepo := s.repoManager.Vtxos()
			roundRepo := s.repoManager.Rounds()

			for _, keys := range vtxoKeys {
				for _, v := range keys {
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
					log.Debugf("vtxo %s:%d redeemed", vtxo.Txid, vtxo.VOut)

					if !vtxo.Spent {
						continue
					}

					log.Debugf("fraud detected on vtxo %s:%d", vtxo.Txid, vtxo.VOut)
					mutx.Lock()

					round, err := roundRepo.GetRoundWithTxid(ctx, vtxo.SpentBy)
					if err != nil {
						// if the round is not found, the utxo may be spent by an async payment redeem tx
						vtxos, err := vtxosRepo.GetVtxos(ctx, []domain.VtxoKey{
							{Txid: vtxo.SpentBy, VOut: 0},
						})
						if err != nil || len(vtxos) <= 0 {
							log.WithError(err).Warn("failed to retrieve round")
							mutx.Unlock()
							continue
						}

						asyncPayVtxo := vtxos[0]
						if asyncPayVtxo.Redeemed { // redeem tx is already onchain
							mutx.Unlock()
							continue
						}

						log.Debugf("vtxo %s has been spent by async payment", vtxo.Txid)

						redeemTxHex, err := s.builder.FinalizeAndExtract(asyncPayVtxo.AsyncPayment.RedeemTx)
						if err != nil {
							log.WithError(err).Warn("failed to finalize redeem tx")
							mutx.Unlock()
							continue
						}

						redeemTxid, err := s.wallet.BroadcastTransaction(ctx, redeemTxHex)
						if err != nil {
							log.WithError(err).Warn("failed to broadcast redeem tx")
							mutx.Unlock()
							continue
						}

						log.Debugf("broadcasted redeem tx %s", redeemTxid)
						mutx.Unlock()
						continue
					}

					connectorTxid, connectorVout, err := s.getNextConnector(ctx, *round)
					if err != nil {
						log.WithError(err).Warn("failed to retrieve next connector")
						mutx.Unlock()
						continue
					}

					log.Debugf("found next connector %s:%d", connectorTxid, connectorVout)

					forfeitTx, err := findForfeitTxBitcoin(round.ForfeitTxs, connectorTxid, connectorVout, vtxo.Txid, vtxo.VOut)
					if err != nil {
						log.WithError(err).Warn("failed to retrieve forfeit tx")
						mutx.Unlock()
						continue
					}

					if err := s.wallet.LockConnectorUtxos(ctx, []ports.TxOutpoint{txOutpoint{connectorTxid, connectorVout}}); err != nil {
						log.WithError(err).Warn("failed to lock connector utxos")
						mutx.Unlock()
						continue
					}

					signedForfeitTx, err := s.wallet.SignTransactionTapscript(ctx, forfeitTx, nil)
					if err != nil {
						log.WithError(err).Warn("failed to sign vtxo input in forfeit tx")
						mutx.Unlock()
						continue
					}

					forfeitTxHex, err := s.builder.FinalizeAndExtract(signedForfeitTx)
					if err != nil {
						log.WithError(err).Warn("failed to finalize forfeit tx")
						mutx.Unlock()
						continue
					}

					forfeitTxid, err := s.wallet.BroadcastTransaction(ctx, forfeitTxHex)
					if err != nil {
						log.WithError(err).Warn("failed to broadcast forfeit tx")
						mutx.Unlock()
						continue
					}

					mutx.Unlock()
					log.Debugf("broadcasted forfeit tx %s", forfeitTxid)
				}
			}
		}(vtxoKeys)
	}
}

func (s *covenantlessService) getNextConnector(
	ctx context.Context,
	round domain.Round,
) (string, uint32, error) {
	lastConnectorPtx, err := psbt.NewFromRawBytes(strings.NewReader(round.Connectors[len(round.Connectors)-1]), true)
	if err != nil {
		return "", 0, err
	}

	lastOutput := lastConnectorPtx.UnsignedTx.TxOut[len(lastConnectorPtx.UnsignedTx.TxOut)-1]
	connectorAmount := lastOutput.Value

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
		if u.GetValue() == uint64(connectorAmount) {
			return u.GetTxid(), u.GetIndex(), nil
		}
	}

	for _, u := range utxos {
		if u.GetValue() > uint64(connectorAmount) {
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
							return "", 0, fmt.Errorf("failed to broadcast connector tx: %s", err)
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

func findForfeitTxBitcoin(
	forfeits []string, connectorTxid string, connectorVout uint32, vtxoTxid string, vtxoVout uint32,
) (string, error) {
	for _, forfeit := range forfeits {
		forfeitTx, err := psbt.NewFromRawBytes(strings.NewReader(forfeit), true)
		if err != nil {
			return "", err
		}

		connector := forfeitTx.UnsignedTx.TxIn[0]
		vtxoInput := forfeitTx.UnsignedTx.TxIn[1]

		if connector.PreviousOutPoint.Hash.String() == connectorTxid &&
			connector.PreviousOutPoint.Index == connectorVout &&
			vtxoInput.PreviousOutPoint.Hash.String() == vtxoTxid &&
			vtxoInput.PreviousOutPoint.Index == vtxoVout {
			return forfeit, nil
		}
	}

	return "", fmt.Errorf("forfeit tx not found")
}

// musigSigningSession holds the state of ephemeral nonces and signatures in order to coordinate the signing of the tree
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
