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
	"github.com/ark-network/ark/common/note"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	log "github.com/sirupsen/logrus"
)

const marketHourDelta = 5 * time.Minute

type covenantlessService struct {
	network             common.Network
	pubkey              *secp256k1.PublicKey
	vtxoTreeExpiry      common.RelativeLocktime
	roundInterval       int64
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

	// cached data for the current round
	lastEvent           domain.RoundEvent
	currentRoundLock    sync.Mutex
	currentRound        *domain.Round
	treeSigningSessions map[string]*musigSigningSession
}

func NewCovenantlessService(
	network common.Network,
	roundInterval int64,
	vtxoTreeExpiry, unilateralExitDelay, boardingExitDelay common.RelativeLocktime,
	nostrDefaultRelays []string,
	walletSvc ports.WalletService, repoManager ports.RepoManager,
	builder ports.TxBuilder, scanner ports.BlockchainScanner,
	scheduler ports.SchedulerService,
	noteUriPrefix string,
	marketHourStartTime, marketHourEndTime time.Time,
	marketHourPeriod, marketHourRoundInterval time.Duration,
) (Service, error) {
	pubkey, err := walletSvc.GetPubkey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pubkey: %s", err)
	}

	// Try to load market hours from DB first
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

	svc := &covenantlessService{
		network:             network,
		pubkey:              pubkey,
		vtxoTreeExpiry:      vtxoTreeExpiry,
		roundInterval:       roundInterval,
		unilateralExitDelay: unilateralExitDelay,
		wallet:              walletSvc,
		repoManager:         repoManager,
		builder:             builder,
		scanner:             scanner,
		sweeper:             newSweeper(walletSvc, repoManager, builder, scheduler, noteUriPrefix),
		txRequests:          newTxRequestsQueue(),
		forfeitTxs:          newForfeitTxsMap(builder),
		eventsCh:            make(chan domain.RoundEvent),
		transactionEventsCh: make(chan TransactionEvent),
		currentRoundLock:    sync.Mutex{},
		treeSigningSessions: make(map[string]*musigSigningSession),
		boardingExitDelay:   boardingExitDelay,
		nostrDefaultRelays:  nostrDefaultRelays,
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

func (s *covenantlessService) SubmitRedeemTx(
	ctx context.Context, redeemTx string,
) (string, error) {
	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(redeemTx), true)
	if err != nil {
		return "", fmt.Errorf("failed to parse redeem tx: %s", err)
	}

	vtxoRepo := s.repoManager.Vtxos()

	expiration := int64(0)
	roundTxid := ""

	ins := make([]common.VtxoInput, 0)

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(redeemTx), true)
	if err != nil {
		return "", fmt.Errorf("failed to parse redeem tx: %s", err)
	}

	spentVtxoKeys := make([]domain.VtxoKey, 0, len(ptx.Inputs))
	for _, input := range ptx.UnsignedTx.TxIn {
		spentVtxoKeys = append(spentVtxoKeys, domain.VtxoKey{
			Txid: input.PreviousOutPoint.Hash.String(),
			VOut: input.PreviousOutPoint.Index,
		})
	}

	spentVtxos, err := vtxoRepo.GetVtxos(ctx, spentVtxoKeys)
	if err != nil {
		return "", fmt.Errorf("failed to get vtxos: %s", err)
	}

	if len(spentVtxos) != len(spentVtxoKeys) {
		return "", fmt.Errorf("some vtxos not found")
	}

	vtxoMap := make(map[wire.OutPoint]domain.Vtxo)
	for _, vtxo := range spentVtxos {
		hash, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return "", fmt.Errorf("failed to parse vtxo txid: %s", err)
		}
		vtxoMap[wire.OutPoint{Hash: *hash, Index: vtxo.VOut}] = vtxo
	}

	sumOfInputs := int64(0)
	for inputIndex, input := range ptx.Inputs {
		if input.WitnessUtxo == nil {
			return "", fmt.Errorf("missing witness utxo")
		}

		if len(input.TaprootLeafScript) == 0 {
			return "", fmt.Errorf("missing tapscript leaf")
		}

		tapscript := input.TaprootLeafScript[0]

		if len(input.TaprootScriptSpendSig) == 0 {
			return "", fmt.Errorf("missing tapscript spend sig")
		}

		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint

		vtxo, exists := vtxoMap[outpoint]
		if !exists {
			return "", fmt.Errorf("vtxo not found")
		}

		// make sure we don't use the same vtxo twice
		delete(vtxoMap, outpoint)

		if vtxo.Spent {
			return "", fmt.Errorf("vtxo already spent")
		}

		if vtxo.Redeemed {
			return "", fmt.Errorf("vtxo already redeemed")
		}

		if vtxo.Swept {
			return "", fmt.Errorf("vtxo already swept")
		}

		sumOfInputs += input.WitnessUtxo.Value

		if inputIndex == 0 || vtxo.ExpireAt < expiration {
			roundTxid = vtxo.RoundTxid
			expiration = vtxo.ExpireAt
		}

		// verify that the user signs a forfeit closure
		var userPubkey *secp256k1.PublicKey

		serverXOnlyPubkey := schnorr.SerializePubKey(s.pubkey)

		for _, sig := range input.TaprootScriptSpendSig {
			if !bytes.Equal(sig.XOnlyPubKey, serverXOnlyPubkey) {
				parsed, err := schnorr.ParsePubKey(sig.XOnlyPubKey)
				if err != nil {
					return "", fmt.Errorf("failed to parse pubkey: %s", err)
				}
				userPubkey = parsed
				break
			}
		}

		if userPubkey == nil {
			return "", fmt.Errorf("redeem transaction is not signed")
		}

		vtxoPubkeyBuf, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return "", fmt.Errorf("failed to decode vtxo pubkey: %s", err)
		}

		vtxoPubkey, err := schnorr.ParsePubKey(vtxoPubkeyBuf)
		if err != nil {
			return "", fmt.Errorf("failed to parse vtxo pubkey: %s", err)
		}

		// verify witness utxo
		pkscript, err := common.P2TRScript(vtxoPubkey)
		if err != nil {
			return "", fmt.Errorf("failed to get pkscript: %s", err)
		}

		if !bytes.Equal(input.WitnessUtxo.PkScript, pkscript) {
			return "", fmt.Errorf("witness utxo script mismatch")
		}

		if input.WitnessUtxo.Value != int64(vtxo.Amount) {
			return "", fmt.Errorf("witness utxo value mismatch")
		}

		// verify forfeit closure script
		closure, err := tree.DecodeClosure(tapscript.Script)
		if err != nil {
			return "", fmt.Errorf("failed to decode forfeit closure: %s", err)
		}

		var locktime *common.AbsoluteLocktime

		switch c := closure.(type) {
		case *tree.CLTVMultisigClosure:
			locktime = &c.Locktime
		case *tree.MultisigClosure, *tree.ConditionMultisigClosure:
		default:
			return "", fmt.Errorf("invalid forfeit closure script")
		}

		if locktime != nil {
			blocktimestamp, err := s.wallet.GetCurrentBlockTime(ctx)
			if err != nil {
				return "", fmt.Errorf("failed to get current block time: %s", err)
			}
			if !locktime.IsSeconds() {
				if *locktime > common.AbsoluteLocktime(blocktimestamp.Height) {
					return "", fmt.Errorf("forfeit closure is CLTV locked, %d > %d (block time)", *locktime, blocktimestamp.Time)
				}
			} else {
				if *locktime > common.AbsoluteLocktime(blocktimestamp.Time) {
					return "", fmt.Errorf("forfeit closure is CLTV locked, %d > %d (block time)", *locktime, blocktimestamp.Time)
				}
			}
		}

		ctrlBlock, err := txscript.ParseControlBlock(tapscript.ControlBlock)
		if err != nil {
			return "", fmt.Errorf("failed to parse control block: %s", err)
		}

		ins = append(ins, common.VtxoInput{
			Outpoint: &outpoint,
			Tapscript: &waddrmgr.Tapscript{
				ControlBlock:   ctrlBlock,
				RevealedScript: tapscript.Script,
			},
		})
	}

	dust, err := s.wallet.GetDustAmount(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get dust threshold: %s", err)
	}

	outputs := ptx.UnsignedTx.TxOut

	sumOfOutputs := int64(0)
	for _, out := range outputs {
		sumOfOutputs += out.Value
		if out.Value < int64(dust) {
			return "", fmt.Errorf("output value is less than dust threshold")
		}
	}

	fees := sumOfInputs - sumOfOutputs
	if fees < 0 {
		return "", fmt.Errorf("invalid fees, inputs are less than outputs")
	}

	minFeeRate := s.wallet.MinRelayFeeRate(ctx)

	minFees, err := common.ComputeRedeemTxFee(chainfee.SatPerKVByte(minFeeRate), ins, len(outputs))
	if err != nil {
		return "", fmt.Errorf("failed to compute min fees: %s", err)
	}

	if fees < minFees {
		return "", fmt.Errorf("min relay fee not met, %d < %d", fees, minFees)
	}

	// recompute redeem tx
	rebuiltRedeemTx, err := bitcointree.BuildRedeemTx(ins, outputs)
	if err != nil {
		return "", fmt.Errorf("failed to rebuild redeem tx: %s", err)
	}

	rebuiltPtx, err := psbt.NewFromRawBytes(strings.NewReader(rebuiltRedeemTx), true)
	if err != nil {
		return "", fmt.Errorf("failed to parse rebuilt redeem tx: %s", err)
	}

	rebuiltTxid := rebuiltPtx.UnsignedTx.TxID()
	redeemTxid := redeemPtx.UnsignedTx.TxID()
	if rebuiltTxid != redeemTxid {
		return "", fmt.Errorf("invalid redeem tx")
	}

	// verify the tapscript signatures
	if valid, err := s.builder.VerifyTapscriptPartialSigs(redeemTx); err != nil || !valid {
		return "", fmt.Errorf("invalid tx signature: %s", err)
	}

	if expiration == 0 {
		return "", fmt.Errorf("no valid vtxo found")
	}

	if roundTxid == "" {
		return "", fmt.Errorf("no valid vtxo found")
	}

	// sign the redeem tx

	signedRedeemTx, err := s.wallet.SignTransactionTapscript(ctx, redeemTx, nil)
	if err != nil {
		return "", fmt.Errorf("failed to sign redeem tx: %s", err)
	}

	// Create new vtxos, update spent vtxos state
	newVtxos := make([]domain.Vtxo, 0, len(redeemPtx.UnsignedTx.TxOut))
	for outIndex, out := range outputs {
		vtxoTapKey, err := schnorr.ParsePubKey(out.PkScript[2:])
		if err != nil {
			return "", fmt.Errorf("failed to parse vtxo taproot key: %s", err)
		}

		vtxoPubkey := hex.EncodeToString(schnorr.SerializePubKey(vtxoTapKey))

		newVtxos = append(newVtxos, domain.Vtxo{
			VtxoKey: domain.VtxoKey{
				Txid: redeemTxid,
				VOut: uint32(outIndex),
			},
			PubKey:    vtxoPubkey,
			Amount:    uint64(out.Value),
			ExpireAt:  expiration,
			RoundTxid: roundTxid,
			RedeemTx:  signedRedeemTx,
			CreatedAt: time.Now().Unix(),
		})
	}

	if err := s.repoManager.Vtxos().AddVtxos(ctx, newVtxos); err != nil {
		return "", fmt.Errorf("failed to add vtxos: %s", err)
	}
	log.Infof("added %d vtxos", len(newVtxos))
	if err := s.startWatchingVtxos(newVtxos); err != nil {
		log.WithError(err).Warn(
			"failed to start watching vtxos",
		)
	}
	log.Debugf("started watching %d vtxos", len(newVtxos))

	if err := s.repoManager.Vtxos().SpendVtxos(ctx, spentVtxoKeys, redeemTxid); err != nil {
		return "", fmt.Errorf("failed to spend vtxo: %s", err)
	}
	log.Infof("spent %d vtxos", len(spentVtxos))

	go func() {
		s.transactionEventsCh <- RedeemTransactionEvent{
			RedeemTxid:     redeemTxid,
			SpentVtxos:     spentVtxoKeys,
			SpendableVtxos: newVtxos,
		}
	}()

	return signedRedeemTx, nil
}

func (s *covenantlessService) GetBoardingAddress(
	ctx context.Context, userPubkey *secp256k1.PublicKey,
) (address string, scripts []string, err error) {
	vtxoScript := bitcointree.NewDefaultVtxoScript(s.pubkey, userPubkey, s.boardingExitDelay)

	tapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return "", nil, fmt.Errorf("failed to get taproot key: %s", err)
	}

	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(tapKey), s.chainParams(),
	)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get address: %s", err)
	}

	scripts, err = vtxoScript.Encode()
	if err != nil {
		return "", nil, fmt.Errorf("failed to encode vtxo script: %s", err)
	}

	address = addr.EncodeAddress()

	return
}

func (s *covenantlessService) SpendNotes(ctx context.Context, notes []note.Note) (string, error) {
	notesRepo := s.repoManager.Notes()

	for _, note := range notes {
		// verify the note signature
		hash := note.Hash()

		valid, err := s.wallet.VerifyMessageSignature(ctx, hash, note.Signature)
		if err != nil {
			return "", fmt.Errorf("failed to verify note signature: %s", err)
		}

		if !valid {
			return "", fmt.Errorf("invalid note signature %s", note)
		}

		// verify that the note is spendable
		spent, err := notesRepo.Contains(ctx, note.ID)
		if err != nil {
			return "", fmt.Errorf("failed to check if note is spent: %s", err)
		}

		if spent {
			return "", fmt.Errorf("note already spent: %s", note)
		}
	}

	request, err := domain.NewTxRequest(make([]domain.Vtxo, 0))
	if err != nil {
		return "", fmt.Errorf("failed to create tx request: %s", err)
	}

	if err := s.txRequests.pushWithNotes(*request, notes); err != nil {
		return "", fmt.Errorf("failed to push tx requests: %s", err)
	}

	return request.Id, nil
}

func (s *covenantlessService) SpendVtxos(ctx context.Context, inputs []ports.Input) (string, error) {
	vtxosInputs := make([]domain.Vtxo, 0)
	boardingInputs := make([]ports.BoardingInput, 0)

	now := time.Now().Unix()

	boardingTxs := make(map[string]wire.MsgTx, 0) // txid -> txhex

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

				var tx wire.MsgTx
				if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
					return "", fmt.Errorf("failed to deserialize tx %s: %s", input.Txid, err)
				}

				confirmed, _, blocktime, err := s.wallet.IsTransactionConfirmed(ctx, input.Txid)
				if err != nil {
					return "", fmt.Errorf("failed to check tx %s: %s", input.Txid, err)
				}

				if !confirmed {
					return "", fmt.Errorf("tx %s not confirmed", input.Txid)
				}

				vtxoScript, err := bitcointree.ParseVtxoScript(input.Tapscripts)
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

		vtxoScript, err := bitcointree.ParseVtxoScript(input.Tapscripts)
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

func (s *covenantlessService) newBoardingInput(tx wire.MsgTx, input ports.Input) (*ports.BoardingInput, error) {
	if len(tx.TxOut) <= int(input.VtxoKey.VOut) {
		return nil, fmt.Errorf("output not found")
	}

	output := tx.TxOut[input.VtxoKey.VOut]

	boardingScript, err := bitcointree.ParseVtxoScript(input.Tapscripts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse boarding descriptor: %s", err)
	}

	tapKey, _, err := boardingScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("failed to get taproot key: %s", err)
	}

	expectedScriptPubkey, err := common.P2TRScript(tapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get script pubkey: %s", err)
	}

	if !bytes.Equal(output.PkScript, expectedScriptPubkey) {
		return nil, fmt.Errorf("descriptor does not match script in transaction output")
	}

	if err := boardingScript.Validate(s.pubkey, s.unilateralExitDelay); err != nil {
		return nil, err
	}

	return &ports.BoardingInput{
		Amount: uint64(output.Value),
		Input:  input,
	}, nil
}

func (s *covenantlessService) ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver) error {
	// Check credentials
	request, ok := s.txRequests.view(creds)
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

	if err := request.AddReceivers(receivers); err != nil {
		return err
	}
	return s.txRequests.update(*request)
}

func (s *covenantlessService) UpdateTxRequestStatus(_ context.Context, id string) error {
	return s.txRequests.updatePingTimestamp(id)
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

func (s *covenantlessService) ListVtxos(ctx context.Context, address string) ([]domain.Vtxo, []domain.Vtxo, error) {
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

func (s *covenantlessService) GetEventsChannel(ctx context.Context) <-chan domain.RoundEvent {
	return s.eventsCh
}

func (s *covenantlessService) GetTransactionEventsChannel(ctx context.Context) <-chan TransactionEvent {
	return s.transactionEventsCh
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

	forfeitAddr, err := s.wallet.GetForfeitAddress(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get forfeit address: %s", err)
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
		ForfeitAddress:      forfeitAddr,
		NextMarketHour: &NextMarketHour{
			StartTime:     marketHourNextStart,
			EndTime:       marketHourNextEnd,
			Period:        marketHourConfig.Period,
			RoundInterval: marketHourConfig.RoundInterval,
		},
	}, nil
}

func calcNextMarketHour(marketHourStartTime, marketHourEndTime time.Time, period, marketHourDelta time.Duration, now time.Time) (time.Time, time.Time, error) {
	// Validate input parameters
	if period <= 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("period must be greater than 0")
	}
	if !marketHourEndTime.After(marketHourStartTime) {
		return time.Time{}, time.Time{}, fmt.Errorf("market hour end time must be after start time")
	}

	// Calculate the duration of the market hour
	duration := marketHourEndTime.Sub(marketHourStartTime)

	// Calculate the number of periods since the initial marketHourStartTime
	elapsed := now.Sub(marketHourStartTime)
	var n int64
	if elapsed >= 0 {
		n = int64(elapsed / period)
	} else {
		n = int64((elapsed - period + 1) / period)
	}

	// Calculate the current market hour start and end times
	currentStartTime := marketHourStartTime.Add(time.Duration(n) * period)
	currentEndTime := currentStartTime.Add(duration)

	// Adjust if now is before the currentStartTime
	if now.Before(currentStartTime) {
		n -= 1
		currentStartTime = marketHourStartTime.Add(time.Duration(n) * period)
		currentEndTime = currentStartTime.Add(duration)
	}

	timeUntilEnd := currentEndTime.Sub(now)

	if !now.Before(currentStartTime) && now.Before(currentEndTime) && timeUntilEnd >= marketHourDelta {
		// Return the current market hour
		return currentStartTime, currentEndTime, nil
	} else {
		// Move to the next market hour
		n += 1
		nextStartTime := marketHourStartTime.Add(time.Duration(n) * period)
		nextEndTime := nextStartTime.Add(duration)
		return nextStartTime, nextEndTime, nil
	}
}

func (s *covenantlessService) RegisterCosignerPubkey(ctx context.Context, requestID string, pubkey string) error {
	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		return fmt.Errorf("failed to decode hex pubkey: %s", err)
	}

	ephemeralPubkey, err := secp256k1.ParsePubKey(pubkeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse pubkey: %s", err)
	}

	return s.txRequests.pushEphemeralKey(requestID, ephemeralPubkey)
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

	if len(session.nonces) == session.nbCosigners-1 { // exclude the server
		go func() {
			session.nonceDoneC <- struct{}{}
		}()
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

	if len(session.signatures) == session.nbCosigners-1 { // exclude the server
		go func() {
			session.sigDoneC <- struct{}{}
		}()
	}

	return nil
}

func (s *covenantlessService) SetNostrRecipient(ctx context.Context, nostrRecipient string, signedVtxoOutpoints []SignedVtxoOutpoint) error {
	nprofileRecipient, err := nip19toNostrProfile(nostrRecipient, s.nostrDefaultRelays)
	if err != nil {
		return fmt.Errorf("failed to convert nostr recipient: %s", err)
	}

	if err := validateProofs(ctx, s.repoManager.Vtxos(), signedVtxoOutpoints); err != nil {
		return err
	}

	vtxoKeys := make([]domain.VtxoKey, 0, len(signedVtxoOutpoints))
	for _, signedVtxo := range signedVtxoOutpoints {
		vtxoKeys = append(vtxoKeys, signedVtxo.Outpoint)
	}

	return s.repoManager.Entities().Add(
		ctx,
		domain.Entity{
			NostrRecipient: nprofileRecipient,
		},
		vtxoKeys,
	)
}

func (s *covenantlessService) DeleteNostrRecipient(ctx context.Context, signedVtxoOutpoints []SignedVtxoOutpoint) error {
	if err := validateProofs(ctx, s.repoManager.Vtxos(), signedVtxoOutpoints); err != nil {
		return err
	}

	vtxoKeys := make([]domain.VtxoKey, 0, len(signedVtxoOutpoints))
	for _, signedVtxo := range signedVtxoOutpoints {
		vtxoKeys = append(vtxoKeys, signedVtxo.Outpoint)
	}

	return s.repoManager.Entities().Delete(ctx, vtxoKeys)
}

func (s *covenantlessService) start() {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("recovered from panic in start: %v", r)
		}
	}()

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
	s.currentRound = round

	defer func() {
		time.Sleep(time.Duration(s.roundInterval/3) * time.Second)
		s.startFinalization()
	}()

	log.Debugf("started registration stage for new round: %s", round.Id)
}

func (s *covenantlessService) startFinalization() {
	ctx := context.Background()
	round := s.currentRound

	roundRemainingDuration := time.Duration((s.roundInterval/3)*2-1) * time.Second
	thirdOfRemainingDuration := time.Duration(roundRemainingDuration / 3)

	var notes []note.Note
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
		s.finalizeRound(notes)
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
	requests, boardingInputs, cosigners, redeeemedNotes := s.txRequests.pop(num)
	if len(requests) > len(cosigners) {
		err := fmt.Errorf("missing ephemeral key for tx requests")
		round.Fail(fmt.Errorf("round aborted: %s", err))
		log.WithError(err).Debugf("round %s aborted", round.Id)
		return
	}

	notes = redeeemedNotes

	if _, err := round.RegisterTxRequests(requests); err != nil {
		round.Fail(fmt.Errorf("failed to register tx requests: %s", err))
		log.WithError(err).Warn("failed to register tx requests")
		return
	}

	connectorAddresses, err := s.repoManager.Rounds().GetSweptRoundsConnectorAddress(ctx)
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

	unsignedRoundTx, vtxoTree, connectorAddress, connectors, err := s.builder.BuildRoundTx(
		s.pubkey, requests, boardingInputs, connectorAddresses, cosigners...,
	)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create round tx: %s", err))
		log.WithError(err).Warn("failed to create round tx")
		return
	}
	log.Debugf("round tx created for round %s", round.Id)

	s.forfeitTxs.init(connectors, requests)

	if len(vtxoTree) > 0 {
		log.Debugf("signing vtxo tree for round %s", round.Id)

		signingSession := newMusigSigningSession(len(cosigners))
		s.treeSigningSessions[round.Id] = signingSession

		log.Debugf("signing session created for round %s", round.Id)

		s.currentRound.UnsignedTx = unsignedRoundTx
		// send back the unsigned tree & all cosigners pubkeys
		s.propagateRoundSigningStartedEvent(vtxoTree, cosigners)

		sweepClosure := tree.CSVMultisigClosure{
			MultisigClosure: tree.MultisigClosure{PubKeys: []*secp256k1.PublicKey{s.pubkey}},
			Locktime:        s.vtxoTreeExpiry,
		}

		sweepScript, err := sweepClosure.Script()
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

		sweepLeaf := txscript.NewBaseTapLeaf(sweepScript)
		sweepTapTree := txscript.AssembleTaprootScriptTree(sweepLeaf)
		root := sweepTapTree.RootNode.TapHash()

		coordinator, err := bitcointree.NewTreeCoordinatorSession(sharedOutputAmount, vtxoTree, root.CloneBytes(), cosigners)
		if err != nil {
			round.Fail(fmt.Errorf("failed to create tree coordinator: %s", err))
			log.WithError(err).Warn("failed to create tree coordinator")
			return
		}

		serverSignerSession := bitcointree.NewTreeSignerSession(
			ephemeralKey, sharedOutputAmount, vtxoTree, root.CloneBytes(),
		)

		nonces, err := serverSignerSession.GetNonces()
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

		if err := serverSignerSession.SetKeys(cosigners); err != nil {
			round.Fail(fmt.Errorf("failed to set keys: %s", err))
			log.WithError(err).Warn("failed to set keys")
			return
		}

		if err := serverSignerSession.SetAggregatedNonces(aggragatedNonces); err != nil {
			round.Fail(fmt.Errorf("failed to set aggregated nonces: %s", err))
			log.WithError(err).Warn("failed to set aggregated nonces")
			return
		}

		// sign the tree as server
		serverTreeSigs, err := serverSignerSession.Sign()
		if err != nil {
			round.Fail(fmt.Errorf("failed to sign tree: %s", err))
			log.WithError(err).Warn("failed to sign tree")
			return
		}

		if err := coordinator.AddSig(ephemeralKey.PubKey(), serverTreeSigs); err != nil {
			round.Fail(fmt.Errorf("failed to add signature: %s", err))
			log.WithError(err).Warn("failed to add signature")
			return
		}

		log.Debugf("tree signed by us for round %s", round.Id)

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

		log.Debugf("vtxo tree signed for round %s", round.Id)

		vtxoTree = signedTree
	}

	if _, err := round.StartFinalization(
		connectorAddress, connectors, vtxoTree, unsignedRoundTx,
	); err != nil {
		round.Fail(fmt.Errorf("failed to start finalization: %s", err))
		log.WithError(err).Warn("failed to start finalization")
		return
	}

	log.Debugf("started finalization stage for round: %s", round.Id)
}

func (s *covenantlessService) propagateRoundSigningStartedEvent(
	unsignedVtxoTree tree.VtxoTree, cosigners []*secp256k1.PublicKey,
) {
	ev := RoundSigningStarted{
		Id:               s.currentRound.Id,
		UnsignedVtxoTree: unsignedVtxoTree,
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

func (s *covenantlessService) finalizeRound(notes []note.Note) {
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

	forfeitTxs, err := s.forfeitTxs.pop()
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to finalize round: %s", err))
		log.WithError(err).Warn("failed to finalize round")
		return
	}

	log.Debugf("signing round transaction %s\n", round.Id)

	boardingInputsIndexes := make([]int, 0)
	boardingInputs := make([]domain.VtxoKey, 0)
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

			boardingInputsIndexes = append(boardingInputsIndexes, i)
			boardingInputs = append(boardingInputs, domain.VtxoKey{
				Txid: roundTx.UnsignedTx.TxIn[i].PreviousOutPoint.Hash.String(),
				VOut: roundTx.UnsignedTx.TxIn[i].PreviousOutPoint.Index,
			})
		}
	}

	signedRoundTx := round.UnsignedTx

	if len(boardingInputsIndexes) > 0 {
		signedRoundTx, err = s.wallet.SignTransactionTapscript(ctx, signedRoundTx, boardingInputsIndexes)
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
		changes = round.Fail(fmt.Errorf("failed to broadcast round tx: %s", err))
		return
	}

	changes, err = round.EndFinalization(forfeitTxs, txid)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to finalize round: %s", err))
		log.WithError(err).Warn("failed to finalize round")
		return
	}

	// mark the notes as spent
	for _, note := range notes {
		if err := s.repoManager.Notes().Add(ctx, note.ID); err != nil {
			log.WithError(err).Warn("failed to mark note as spent")
		}
	}

	go func() {
		s.transactionEventsCh <- RoundTransactionEvent{
			RoundTxid:             round.Txid,
			SpentVtxos:            getSpentVtxos(round.TxRequests),
			SpendableVtxos:        s.getNewVtxos(round),
			ClaimedBoardingInputs: boardingInputs,
		}
	}()

	log.Debugf("finalized round %s with round tx %s", round.Id, round.Txid)
}

func (s *covenantlessService) listenToScannerNotifications() {
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
					log.Errorf("recovered from panic in GetVtxos: %v", r)
				}
			}()

			for _, keys := range vtxoKeys {
				for _, v := range keys {
					vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.VtxoKey{v.VtxoKey})
					if err != nil {
						log.WithError(err).Warn("failed to retrieve vtxos, skipping...")
						return
					}
					vtxo := vtxos[0]

					if !vtxo.Redeemed {
						go func() {
							defer func() {
								if r := recover(); r != nil {
									log.Errorf("recovered from panic in markAsRedeemed: %v", r)
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
									log.Errorf("recovered from panic in reactToFraud: %v", r)
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
}

func (s *covenantlessService) propagateEvents(round *domain.Round) {
	lastEvent := round.Events()[len(round.Events())-1]
	switch e := lastEvent.(type) {
	case domain.RoundFinalizationStarted:
		ev := domain.RoundFinalizationStarted{
			Id:              e.Id,
			VtxoTree:        e.VtxoTree,
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

func (s *covenantlessService) scheduleSweepVtxosForRound(round *domain.Round) {
	// Schedule the sweeping procedure only for completed round.
	if !round.IsEnded() {
		return
	}

	expirationTimestamp := s.sweeper.scheduler.AddNow(int64(s.vtxoTreeExpiry.Value))

	if err := s.sweeper.schedule(expirationTimestamp, round.Txid, round.VtxoTree); err != nil {
		log.WithError(err).Warn("failed to schedule sweep tx")
	}
}

func (s *covenantlessService) getNewVtxos(round *domain.Round) []domain.Vtxo {
	if len(round.VtxoTree) <= 0 {
		return nil
	}

	createdAt := time.Now().Unix()

	leaves := round.VtxoTree.Leaves()
	vtxos := make([]domain.Vtxo, 0)
	for _, node := range leaves {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
		if err != nil {
			log.WithError(err).Warn("failed to parse tx")
			continue
		}
		for i, out := range tx.UnsignedTx.TxOut {
			vtxoTapKey, err := schnorr.ParsePubKey(out.PkScript[2:])
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

func (s *covenantlessService) extractVtxosScripts(vtxos []domain.Vtxo) ([]string, error) {
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

func (s *covenantlessService) chainParams() *chaincfg.Params {
	switch s.network.Name {
	case common.Bitcoin.Name:
		return &chaincfg.MainNetParams
	case common.BitcoinTestNet.Name:
		return &chaincfg.TestNet3Params
	case common.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
	default:
		return nil
	}
}

func (s *covenantlessService) reactToFraud(ctx context.Context, vtxo domain.Vtxo, mutx *sync.Mutex) error {
	mutx.Lock()
	defer mutx.Unlock()
	roundRepo := s.repoManager.Rounds()

	round, err := roundRepo.GetRoundWithTxid(ctx, vtxo.SpentBy)
	if err != nil {
		vtxosRepo := s.repoManager.Vtxos()

		// If the round is not found, the utxo may be spent by an out of round tx
		vtxos, err := vtxosRepo.GetVtxos(ctx, []domain.VtxoKey{
			{Txid: vtxo.SpentBy, VOut: 0},
		})
		if err != nil || len(vtxos) <= 0 {
			return fmt.Errorf("failed to retrieve round: %s", err)
		}

		storedVtxo := vtxos[0]
		if storedVtxo.Redeemed { // redeem tx is already onchain
			return nil
		}

		log.Debugf("vtxo %s:%d has been spent by out of round transaction", vtxo.Txid, vtxo.VOut)

		redeemTxHex, err := s.builder.FinalizeAndExtract(storedVtxo.RedeemTx)
		if err != nil {
			return fmt.Errorf("failed to finalize redeem tx: %s", err)
		}

		redeemTxid, err := s.wallet.BroadcastTransaction(ctx, redeemTxHex)
		if err != nil {
			return fmt.Errorf("failed to broadcast redeem tx: %s", err)
		}

		log.Debugf("broadcasted redeem tx %s", redeemTxid)
		return nil
	}

	connectorTxid, connectorVout, err := s.getNextConnector(ctx, *round)
	if err != nil {
		return fmt.Errorf("failed to get next connector: %s", err)
	}

	log.Debugf("found next connector %s:%d", connectorTxid, connectorVout)

	forfeitTx, err := findForfeitTxBitcoin(round.ForfeitTxs, connectorTxid, connectorVout, vtxo.VtxoKey)
	if err != nil {
		return fmt.Errorf("failed to find forfeit tx: %s", err)
	}

	if err := s.wallet.LockConnectorUtxos(ctx, []ports.TxOutpoint{txOutpoint{connectorTxid, connectorVout}}); err != nil {
		return fmt.Errorf("failed to lock connector utxos: %s", err)
	}

	signedForfeitTx, err := s.wallet.SignTransactionTapscript(ctx, forfeitTx, nil)
	if err != nil {
		return fmt.Errorf("failed to sign forfeit tx: %s", err)
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

func (s *covenantlessService) markAsRedeemed(ctx context.Context, vtxo domain.Vtxo) error {
	if err := s.repoManager.Vtxos().RedeemVtxos(ctx, []domain.VtxoKey{vtxo.VtxoKey}); err != nil {
		return err
	}

	log.Debugf("vtxo %s:%d redeemed", vtxo.Txid, vtxo.VOut)
	return nil
}

func findForfeitTxBitcoin(
	forfeits []string, connectorTxid string, connectorVout uint32, vtxo domain.VtxoKey,
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
			vtxoInput.PreviousOutPoint.Hash.String() == vtxo.Txid &&
			vtxoInput.PreviousOutPoint.Index == vtxo.VOut {
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

func (s *covenantlessService) GetMarketHourConfig(ctx context.Context) (*domain.MarketHour, error) {
	return s.repoManager.MarketHourRepo().Get(ctx)
}

func (s *covenantlessService) UpdateMarketHourConfig(
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
