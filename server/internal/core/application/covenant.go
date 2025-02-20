package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/note"
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
	roundInterval       int64
	vtxoTreeExpiry      common.RelativeLocktime
	unilateralExitDelay common.RelativeLocktime
	boardingExitDelay   common.RelativeLocktime

	nostrDefaultRelays []string

	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder
	scanner     ports.BlockchainScanner
	sweeper     *sweeper

	txRequests *txRequestsQueue
	forfeitTxs *forfeitTxsMap

	eventsCh            chan domain.RoundEvent
	transactionEventsCh chan TransactionEvent

	currentRoundLock sync.Mutex
	currentRound     *domain.Round
	lastEvent        domain.RoundEvent

	numOfBoardingInputs    int
	numOfBoardingInputsMtx sync.RWMutex

	forfeitsBoardingSigsChan chan struct{}
}

func NewCovenantService(
	network common.Network,
	roundInterval int64,
	vtxoTreeExpiry, unilateralExitDelay, boardingExitDelay common.RelativeLocktime,
	nostrDefaultRelays []string,
	walletSvc ports.WalletService, repoManager ports.RepoManager,
	builder ports.TxBuilder, scanner ports.BlockchainScanner,
	scheduler ports.SchedulerService,
	notificationPrefix string,
	marketHourStartTime, marketHourEndTime time.Time, marketHourPeriod, marketHourRoundInterval time.Duration,
) (Service, error) {
	pubkey, err := walletSvc.GetPubkey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pubkey: %s", err)
	}

	marketHour, err := repoManager.MarketHourRepo().Get(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get market hours from db: %w", err)
	}

	if marketHour == nil {
		marketHour = domain.NewMarketHour(marketHourStartTime, marketHourEndTime, marketHourPeriod, marketHourRoundInterval)
		if err := repoManager.MarketHourRepo().Upsert(context.Background(), *marketHour); err != nil {
			return nil, fmt.Errorf("failed to upsert initial market hours to db: %w", err)
		}
	}

	svc := &covenantService{
		network:                  network,
		pubkey:                   pubkey,
		vtxoTreeExpiry:           vtxoTreeExpiry,
		roundInterval:            roundInterval,
		unilateralExitDelay:      unilateralExitDelay,
		boardingExitDelay:        boardingExitDelay,
		wallet:                   walletSvc,
		repoManager:              repoManager,
		builder:                  builder,
		scanner:                  scanner,
		sweeper:                  newSweeper(walletSvc, repoManager, builder, scheduler, notificationPrefix),
		txRequests:               newTxRequestsQueue(),
		forfeitTxs:               newForfeitTxsMap(builder),
		eventsCh:                 make(chan domain.RoundEvent),
		transactionEventsCh:      make(chan TransactionEvent),
		currentRoundLock:         sync.Mutex{},
		nostrDefaultRelays:       nostrDefaultRelays,
		forfeitsBoardingSigsChan: make(chan struct{}, 1),
	}

	repoManager.RegisterEventsHandler(
		func(round *domain.Round) {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Errorf("recovered from panic in propagateEvents: %v", r)
					}
				}()

				svc.propagateEvents(round)
			}()

			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Errorf("recovered from panic in updateVtxoSet and scheduleSweepVtxosForRound: %v", r)
					}
				}()

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

func (s *covenantService) GetBoardingAddress(ctx context.Context, userPubkey *secp256k1.PublicKey) (string, []string, error) {
	vtxoScript := tree.NewDefaultVtxoScript(userPubkey, s.pubkey, s.boardingExitDelay)

	tapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return "", nil, fmt.Errorf("failed to get taproot key: %s", err)
	}

	p2tr, err := payment.FromTweakedKey(tapKey, s.onchainNetwork(), nil)
	if err != nil {
		return "", nil, err
	}

	addr, err := p2tr.TaprootAddress()
	if err != nil {
		return "", nil, err
	}

	scripts, err := vtxoScript.Encode()
	if err != nil {
		return "", nil, err
	}

	return addr, scripts, nil
}

func (s *covenantService) SpendNotes(_ context.Context, _ []note.Note) (string, error) {
	return "", fmt.Errorf("unimplemented")
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

				vtxoScript, err := tree.ParseVtxoScript(input.Tapscripts)
				if err != nil {
					return "", fmt.Errorf("failed to parse boarding descriptor: %s", err)
				}

				exitDelay, err := vtxoScript.SmallestExitDelay()
				if err != nil {
					return "", fmt.Errorf("failed to get exit delay: %s", err)
				}

				// if the exit path is available, forbid registering the boarding utxo
				if blocktime+exitDelay.Seconds() < now {
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

		vtxoScript, err := tree.ParseVtxoScript(input.Tapscripts)
		if err != nil {
			return "", fmt.Errorf("failed to parse boarding descriptor: %s", err)
		}

		tapKey, _, err := vtxoScript.TapTree()
		if err != nil {
			return "", fmt.Errorf("failed to get taproot key: %s", err)
		}

		expectedTapKey, err := vtxo.TapKey()
		if err != nil {
			return "", fmt.Errorf("failed to get taproot key: %s", err)
		}

		if !bytes.Equal(schnorr.SerializePubKey(tapKey), schnorr.SerializePubKey(expectedTapKey)) {
			return "", fmt.Errorf("descriptor does not match vtxo pubkey")
		}

		vtxosInputs = append(vtxosInputs, vtxo)
	}

	request, err := domain.NewTxRequest(vtxosInputs)
	if err != nil {
		return "", err
	}
	if err := s.txRequests.push(*request, boardingInputs); err != nil {
		return "", err
	}
	return request.Id, nil
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

	boardingScript, err := tree.ParseVtxoScript(input.Tapscripts)
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

	if err := boardingScript.Validate(s.pubkey, s.unilateralExitDelay); err != nil {
		return nil, err
	}

	return &ports.BoardingInput{
		Amount: amount,
		Input:  input,
	}, nil
}

func (s *covenantService) ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver, _ *tree.Musig2) error {
	// Check credentials
	request, ok := s.txRequests.view(creds)
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

	if err := request.AddReceivers(receivers); err != nil {
		return err
	}
	return s.txRequests.update(*request, nil)
}

func (s *covenantService) UpdateTxRequestStatus(_ context.Context, id string) error {
	return s.txRequests.updatePingTimestamp(id)
}

func (s *covenantService) SubmitRedeemTx(context.Context, string) (string, string, error) {
	return "", "", fmt.Errorf("unimplemented")
}

func (s *covenantService) SignVtxos(ctx context.Context, forfeitTxs []string) error {
	if err := s.forfeitTxs.sign(forfeitTxs); err != nil {
		return err
	}

	go func() {
		s.currentRoundLock.Lock()
		s.checkForfeitsAndBoardingSigsSent(s.currentRound)
		s.currentRoundLock.Unlock()
	}()

	return nil
}

func (s *covenantService) SignRoundTx(ctx context.Context, signedRoundTx string) error {
	s.currentRoundLock.Lock()
	defer s.currentRoundLock.Unlock()
	currentRound := s.currentRound

	combined, err := s.builder.VerifyAndCombinePartialTx(currentRound.UnsignedTx, signedRoundTx)
	if err != nil {
		return fmt.Errorf("failed to verify and combine partial tx: %s", err)
	}

	s.currentRound.UnsignedTx = combined

	go func() {
		s.currentRoundLock.Lock()
		s.checkForfeitsAndBoardingSigsSent(s.currentRound)
		s.currentRoundLock.Unlock()
	}()

	return nil
}

func (s *covenantService) checkForfeitsAndBoardingSigsSent(currentRound *domain.Round) {
	roundTx, _ := psetv2.NewPsetFromBase64(currentRound.UnsignedTx)
	numOfInputsSigned := 0
	for _, v := range roundTx.Inputs {
		if len(v.TapScriptSig) > 0 {
			if len(v.TapScriptSig[0].Signature) > 0 {
				numOfInputsSigned++
			}
		}
	}

	// Condition: all forfeit txs are signed and
	// the number of signed boarding inputs matches
	// numOfBoardingInputs we expect
	s.numOfBoardingInputsMtx.RLock()
	numOfBoardingInputs := s.numOfBoardingInputs
	s.numOfBoardingInputsMtx.RUnlock()

	if s.forfeitTxs.allSigned() && numOfBoardingInputs == numOfInputsSigned {
		select {
		case s.forfeitsBoardingSigsChan <- struct{}{}:
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func (s *covenantService) ListVtxos(ctx context.Context, address string) ([]domain.Vtxo, []domain.Vtxo, error) {
	decodedAddress, err := common.DecodeAddress(address)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode address: %s", err)
	}

	if !bytes.Equal(schnorr.SerializePubKey(decodedAddress.Server), schnorr.SerializePubKey(s.pubkey)) {
		return nil, nil, fmt.Errorf("address does not match server pubkey")
	}

	pubkey := hex.EncodeToString(schnorr.SerializePubKey(decodedAddress.VtxoTapKey))

	return s.repoManager.Vtxos().GetAllVtxos(ctx, pubkey)
}

func (s *covenantService) GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent {
	return s.eventsCh
}

func (s *covenantService) GetTransactionEventsChannel(ctx context.Context) <-chan TransactionEvent {
	return s.transactionEventsCh
}

func (s *covenantService) GetRoundByTxid(ctx context.Context, roundTxid string) (*domain.Round, error) {
	return s.repoManager.Rounds().GetRoundWithTxid(ctx, roundTxid)
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

	marketHourConfig, err := s.repoManager.MarketHourRepo().Get(ctx)
	if err != nil {
		return nil, err
	}

	marketHourNextStart, marketHourNextEnd, err := calcNextMarketHour(
		marketHourConfig.StartTime,
		marketHourConfig.EndTime,
		marketHourConfig.Period,
		marketHourDelta,
		time.Now(),
	)
	if err != nil {
		return nil, err
	}

	return &ServiceInfo{
		PubKey:              pubkey,
		VtxoTreeExpiry:      int64(s.vtxoTreeExpiry.Value),
		UnilateralExitDelay: int64(s.unilateralExitDelay.Value),
		RoundInterval:       s.roundInterval,
		Network:             s.network.Name,
		Dust:                dust,
		ForfeitAddress:      forfeitAddress,
		NextMarketHour: &NextMarketHour{
			StartTime:     marketHourNextStart,
			EndTime:       marketHourNextEnd,
			Period:        marketHourConfig.Period,
			RoundInterval: marketHourConfig.RoundInterval,
		},
	}, nil
}

func (s *covenantService) RegisterCosignerNonces(context.Context, string, *secp256k1.PublicKey, string) error {
	return ErrTreeSigningNotRequired
}

func (s *covenantService) RegisterCosignerSignatures(context.Context, string, *secp256k1.PublicKey, string) error {
	return ErrTreeSigningNotRequired
}

func (s *covenantService) SetNostrRecipient(ctx context.Context, nostrRecipient string, signedVtxoOutpoints []SignedVtxoOutpoint) error {
	return fmt.Errorf("not implemented")
}

func (s *covenantService) DeleteNostrRecipient(ctx context.Context, signedVtxoOutpoints []SignedVtxoOutpoint) error {
	return fmt.Errorf("not implemented")
}

func (s *covenantService) GetTxRequestQueue(
	ctx context.Context, requestIds ...string,
) ([]TxRequestInfo, error) {
	requests, err := s.txRequests.viewAll(requestIds)
	if err != nil {
		return nil, err
	}

	txReqstInfo := make([]TxRequestInfo, 0, len(requests))
	for _, request := range requests {
		signingType := "branch"
		cosigners := make([]string, 0)
		if request.musig2Data != nil {
			if request.musig2Data.SigningType == tree.SignAll {
				signingType = "all"
			}
			cosigners = request.musig2Data.CosignersPublicKeys
		}

		receivers := make([]struct {
			Address string
			Amount  uint64
		}, 0, len(request.Receivers))
		for _, receiver := range request.Receivers {
			if len(receiver.OnchainAddress) > 0 {
				receivers = append(receivers, struct {
					Address string
					Amount  uint64
				}{
					Address: receiver.OnchainAddress,
					Amount:  receiver.Amount,
				})
				continue
			}

			pubkey, err := hex.DecodeString(receiver.PubKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decode pubkey: %s", err)
			}

			vtxoTapKey, err := schnorr.ParsePubKey(pubkey)
			if err != nil {
				return nil, fmt.Errorf("failed to parse pubkey: %s", err)
			}

			address := common.Address{
				HRP:        s.network.Addr,
				Server:     s.pubkey,
				VtxoTapKey: vtxoTapKey,
			}

			addressStr, err := address.Encode()
			if err != nil {
				return nil, fmt.Errorf("failed to encode address: %s", err)
			}

			receivers = append(receivers, struct {
				Address string
				Amount  uint64
			}{
				Address: addressStr,
				Amount:  receiver.Amount,
			})
		}

		txReqstInfo = append(txReqstInfo, TxRequestInfo{
			Id:             request.Id,
			CreatedAt:      request.timestamp,
			Receivers:      receivers,
			Inputs:         request.Inputs,
			BoardingInputs: request.boardingInputs,
			Notes:          request.notes,
			LastPing:       request.pingTimestamp,
			SigningType:    signingType,
			Cosigners:      cosigners,
		})
	}

	return txReqstInfo, nil
}

func (s *covenantService) DeleteTxRequests(
	ctx context.Context, requestIds ...string,
) error {
	if len(requestIds) == 0 {
		return s.txRequests.deleteAll()
	}

	return s.txRequests.delete(requestIds)
}

func (s *covenantService) start() {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("recovered from panic in start: %v", r)
		}
	}()

	s.startRound()
}

func (s *covenantService) startRound() {
	// reset the forfeit txs map to avoid polluting the next batch of forfeits transactions
	s.forfeitTxs.reset()

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
		roundEndTime := time.Now().Add(time.Duration(s.roundInterval) * time.Second)
		time.Sleep(time.Duration(s.roundInterval/6) * time.Second)
		s.startFinalization(roundEndTime)
	}()

	log.Debugf("started registration stage for new round: %s", round.Id)
}

func (s *covenantService) startFinalization(roundEndTime time.Time) {
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

		s.finalizeRound(roundEndTime)
	}()

	if round.IsFailed() {
		return
	}

	// TODO: understand how many tx requests must be popped from the queue and actually registered for the round
	num := s.txRequests.len()
	if num == 0 {
		roundAborted = true
		err := fmt.Errorf("no tx requests registered")
		round.Fail(fmt.Errorf("round aborted: %s", err))
		log.WithError(err).Debugf("round %s aborted", round.Id)
		return
	}
	if num > txRequestsThreshold {
		num = txRequestsThreshold
	}
	requests, boardingInputs, _, _ := s.txRequests.pop(num)
	if _, err := round.RegisterTxRequests(requests); err != nil {
		round.Fail(fmt.Errorf("failed to register tx requests: %s", err))
		log.WithError(err).Warn("failed to register tx requests")
		return
	}
	s.numOfBoardingInputsMtx.Lock()
	s.numOfBoardingInputs = len(boardingInputs)
	s.numOfBoardingInputsMtx.Unlock()

	sweptRounds, err := s.repoManager.Rounds().GetSweptRoundsConnectorAddress(ctx)
	if err != nil {
		round.Fail(fmt.Errorf("failed to retrieve swept rounds: %s", err))
		log.WithError(err).Warn("failed to retrieve swept rounds")
		return
	}

	unsignedRoundTx, tree, connectorAddress, connectors, err := s.builder.BuildRoundTx(s.pubkey, requests, boardingInputs, sweptRounds, nil)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create round tx: %s", err))
		log.WithError(err).Warn("failed to create round tx")
		return
	}
	log.Debugf("round tx created for round %s", round.Id)

	if err := s.forfeitTxs.init(connectors, requests); err != nil {
		round.Fail(fmt.Errorf("failed to initialize forfeit txs: %s", err))
		log.WithError(err).Warn("failed to initialize forfeit txs")
		return
	}

	_, err = round.StartFinalization(
		connectorAddress, connectors, tree, unsignedRoundTx, s.forfeitTxs.connectorsIndex,
	)
	if err != nil {
		round.Fail(fmt.Errorf("failed to start finalization: %s", err))
		log.WithError(err).Warn("failed to start finalization")
		return
	}

	log.Debugf("started finalization stage for round: %s", round.Id)
}

func (s *covenantService) finalizeRound(roundEndTime time.Time) {
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

	remainingTime := time.Until(roundEndTime)
	select {
	case <-s.forfeitsBoardingSigsChan:
		log.Debug("all forfeit txs and boarding inputs signatures have been sent")
	case <-time.After(remainingTime):
		log.Debug("timeout waiting for forfeit txs and boarding inputs signatures")
	}

	forfeitTxs, err := s.forfeitTxs.pop()
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to finalize round: %s", err))
		log.WithError(err).Warn("failed to finalize round")
		return
	}

	if err := s.verifyForfeitTxsSigs(forfeitTxs); err != nil {
		changes = round.Fail(err)
		log.WithError(err).Warn("failed to validate forfeit txs")
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
		log.Debugf("failed to sign round tx: %s", signedRoundTx)
		log.WithError(err).Warn("failed to sign round tx")
		return
	}

	txid, err := s.wallet.BroadcastTransaction(ctx, signedRoundTx)
	if err != nil {
		log.Debugf("failed to broadcast round tx: %s", signedRoundTx)
		changes = round.Fail(fmt.Errorf("failed to broadcast round tx: %s", err))
		log.WithError(err).Warn("failed to broadcast round tx")
		return
	}

	changes, err = round.EndFinalization(forfeitTxs, txid)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to finalize round: %s", err))
		log.WithError(err).Warn("failed to finalize round")
		return
	}

	log.Debugf("finalized round %s with round tx %s", round.Id, round.Txid)
}

func (s *covenantService) listenToScannerNotifications() {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("recovered from panic in listenToScannerNotifications: %v", r)
		}
	}()

	ctx := context.Background()
	chVtxos := s.scanner.GetNotificationChannel(ctx)

	mutx := &sync.Mutex{}
	for vtxoKeys := range chVtxos {
		go func(vtxoKeys map[string][]ports.VtxoWithValue) {
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("recovered from panic in GetVtxos goroutine: %v", r)
				}
			}()

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
							defer func() {
								if r := recover(); r != nil {
									log.Errorf("recovered from panic in markAsRedeemed goroutine: %v", r)
								}
							}()

							if err := s.markAsRedeemed(ctx, vtxo); err != nil {
								log.WithError(err).Warnf("failed to mark vtxo %s:%d as redeemed", vtxo.Txid, vtxo.VOut)
							}
						}()
					}

					if vtxo.Spent {
						log.Infof("fraud detected on vtxo %s:%d", vtxo.Txid, vtxo.VOut)
						go func() {
							defer func() {
								if r := recover(); r != nil {
									log.Errorf("recovered from panic in reactToFraud goroutine: %v", r)
								}
							}()

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

func (s *covenantService) reactToFraud(ctx context.Context, vtxo domain.Vtxo, mutx *sync.Mutex) error {
	round, err := s.repoManager.Rounds().GetRoundWithTxid(ctx, vtxo.SpentBy)
	if err != nil {
		return fmt.Errorf("failed to retrieve round: %s", err)
	}

	mutx.Lock()
	defer mutx.Unlock()

	forfeitTx, err := findForfeitTxLiquid(round.ForfeitTxs, vtxo.VtxoKey)
	if err != nil {
		return fmt.Errorf("failed to find forfeit tx: %s", err)
	}

	forfeitUtx, err := forfeitTx.UnsignedTx()
	if err != nil {
		return fmt.Errorf("failed to get unsigned forfeit tx: %s", err)
	}

	connector := forfeitUtx.Inputs[0]
	connectorOutpoint := txOutpoint{
		chainhash.Hash(connector.Hash).String(),
		connector.Index,
	}

	branch, err := round.Connectors.Branch(connectorOutpoint.txid)
	if err != nil {
		return fmt.Errorf("failed to get branch: %s", err)
	}

	for _, node := range branch {
		_, err := s.wallet.GetTransaction(ctx, node.Txid)
		if err != nil {
			// TODO sign the tx
			// transaction not found, it means we need to broadcast it
			txHex, err := s.builder.FinalizeAndExtract(node.Tx)
			if err != nil {
				return fmt.Errorf("failed to finalize transaction: %s", err)
			}

			txid, err := s.wallet.BroadcastTransaction(ctx, txHex)
			if err != nil {
				return fmt.Errorf("failed to broadcast transaction: %s", err)
			}

			log.Debugf("broadcasted transaction %s", txid)
		}
	}

	if err := s.wallet.LockConnectorUtxos(ctx, []ports.TxOutpoint{connectorOutpoint}); err != nil {
		return fmt.Errorf("failed to lock connector utxos: %s", err)
	}

	forfeitTxB64, err := forfeitTx.ToBase64()
	if err != nil {
		return fmt.Errorf("failed to encode forfeit tx: %s", err)
	}

	signedForfeitTx, err := s.wallet.SignTransaction(ctx, forfeitTxB64, false)
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
	spentVtxos := getSpentVtxos(round.TxRequests)
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
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("recovered from panic in startWatchingVtxos: %v", r)
				}
			}()

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
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("recovered from panic in RoundTransactionEvent: %v", r)
			}
		}()

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
			RoundTxid:             round.Txid,
			SpentVtxos:            getSpentVtxos(round.TxRequests),
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
			Id:               e.Id,
			VtxoTree:         e.VtxoTree,
			Connectors:       e.Connectors,
			RoundTx:          e.RoundTx,
			MinRelayFeeRate:  int64(s.wallet.MinRelayFeeRate(context.Background())),
			ConnectorAddress: e.ConnectorAddress,
			ConnectorsIndex:  e.ConnectorsIndex,
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

	expirationTime := s.sweeper.scheduler.AddNow(int64(s.vtxoTreeExpiry.Value))

	if err := s.sweeper.schedule(
		expirationTime, round.Txid, round.VtxoTree,
	); err != nil {
		log.WithError(err).Warn("failed to schedule sweep tx")
	}
}

func (s *covenantService) getNewVtxos(round *domain.Round) []domain.Vtxo {
	if len(round.VtxoTree) <= 0 {
		return nil
	}

	createdAt := time.Now().Unix()

	leaves := round.VtxoTree.Leaves()
	vtxos := make([]domain.Vtxo, 0)
	for _, node := range leaves {
		tx, _ := psetv2.NewPsetFromBase64(node.Tx)
		for i, out := range tx.Outputs {
			if len(out.Script) <= 0 {
				continue // skip fee outputs
			}

			vtxoTapKey, err := schnorr.ParsePubKey(out.Script[2:])
			if err != nil {
				log.WithError(err).Warn("failed to parse vtxo tap key")
				continue
			}

			vtxoPubkey := hex.EncodeToString(schnorr.SerializePubKey(vtxoTapKey))

			vtxos = append(vtxos, domain.Vtxo{
				VtxoKey:   domain.VtxoKey{Txid: node.Txid, VOut: uint32(i)},
				PubKey:    vtxoPubkey,
				Amount:    uint64(out.Value),
				RoundTxid: round.Txid,
				CreatedAt: createdAt,
			})
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
	ctx := context.Background()

	expiredRounds, err := s.repoManager.Rounds().GetExpiredRoundsTxid(ctx)
	if err != nil {
		return err
	}

	vtxos := make([]domain.Vtxo, 0)
	for _, txid := range expiredRounds {
		fromRound, err := s.repoManager.Vtxos().GetVtxosForRound(ctx, txid)
		if err != nil {
			log.WithError(err).Warnf("failed to retrieve vtxos for round %s", txid)
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
		vtxoTapKeyBytes, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return nil, err
		}

		vtxoTapKey, err := schnorr.ParsePubKey(vtxoTapKeyBytes)
		if err != nil {
			return nil, err
		}

		script, err := common.P2TRScript(vtxoTapKey)
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

func (s *covenantService) verifyForfeitTxsSigs(txs []string) error {
	nbWorkers := runtime.NumCPU()
	jobs := make(chan string, len(txs))
	errChan := make(chan error, 1)
	wg := sync.WaitGroup{}
	wg.Add(nbWorkers)

	for i := 0; i < nbWorkers; i++ {
		go func() {
			defer wg.Done()

			for tx := range jobs {
				valid, txid, err := s.builder.VerifyTapscriptPartialSigs(tx)
				if err != nil {
					errChan <- fmt.Errorf("failed to validate forfeit tx %s: %s", txid, err)
					return
				}

				if !valid {
					errChan <- fmt.Errorf("invalid signature for forfeit tx %s", txid)
					return
				}
			}
		}()
	}

	for _, tx := range txs {
		select {
		case err := <-errChan:
			return err
		default:
			jobs <- tx
		}
	}
	close(jobs)
	wg.Wait()

	select {
	case err := <-errChan:
		return err
	default:
		close(errChan)
		return nil
	}
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
	forfeits []string, vtxo domain.VtxoKey,
) (*psetv2.Pset, error) {
	for _, forfeit := range forfeits {
		forfeitTx, err := psetv2.NewPsetFromBase64(forfeit)
		if err != nil {
			return nil, err
		}

		vtxoInput := forfeitTx.Inputs[1]

		if chainhash.Hash(vtxoInput.PreviousTxid).String() == vtxo.Txid &&
			vtxoInput.PreviousTxIndex == vtxo.VOut {
			return forfeitTx, nil
		}
	}

	return nil, fmt.Errorf("forfeit tx not found")
}

func (s *covenantService) GetMarketHourConfig(ctx context.Context) (*domain.MarketHour, error) {
	return s.repoManager.MarketHourRepo().Get(ctx)
}

func (s *covenantService) UpdateMarketHourConfig(
	ctx context.Context,
	marketHourStartTime, marketHourEndTime time.Time, period, roundInterval time.Duration,
) error {
	marketHour := domain.NewMarketHour(
		marketHourStartTime,
		marketHourEndTime,
		period,
		roundInterval,
	)
	if err := s.repoManager.MarketHourRepo().Upsert(ctx, *marketHour); err != nil {
		return fmt.Errorf("failed to upsert market hours: %w", err)
	}

	return nil
}
