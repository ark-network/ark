package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bip322"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
)

const marketHourDelta = 5 * time.Minute

type covenantlessService struct {
	network             common.Network
	pubkey              *secp256k1.PublicKey
	vtxoTreeExpiry      common.RelativeLocktime
	roundInterval       time.Duration
	unilateralExitDelay common.RelativeLocktime
	boardingExitDelay   common.RelativeLocktime
	allowCSVBlockType   bool

	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder
	scanner     ports.BlockchainScanner
	sweeper     *sweeper

	txRequests  *txRequestsQueue
	forfeitTxs  *forfeitTxsMap
	offchainTxs *offchainTxsMap

	eventsCh            chan []domain.Event
	transactionEventsCh chan TransactionEvent
	// TODO remove this in v7
	indexerTxEventsCh chan TransactionEvent

	// cached data for the current round
	currentRoundLock    sync.Mutex
	currentRound        *domain.Round
	confirmationSession *confirmationSession
	treeSigningSessions map[string]*musigSigningSession

	// TODO derive this from wallet
	serverSigningKey    *secp256k1.PrivateKey
	serverSigningPubKey *secp256k1.PublicKey

	numOfBoardingInputs    int
	numOfBoardingInputsMtx sync.RWMutex

	forfeitsBoardingSigsChan chan struct{}

	roundMinParticipantsCount int64
	roundMaxParticipantsCount int64
	utxoMaxAmount             int64
	utxoMinAmount             int64
	vtxoMaxAmount             int64
	vtxoMinSettlementAmount   int64
	vtxoMinOffchainTxAmount   int64
}

func NewService(
	network common.Network,
	roundInterval int64,
	vtxoTreeExpiry, unilateralExitDelay, boardingExitDelay common.RelativeLocktime,
	walletSvc ports.WalletService, repoManager ports.RepoManager,
	builder ports.TxBuilder, scanner ports.BlockchainScanner,
	scheduler ports.SchedulerService,
	noteUriPrefix string,
	marketHourStartTime, marketHourEndTime time.Time,
	marketHourPeriod, marketHourRoundInterval time.Duration,
	roundMinParticipantsCount, roundMaxParticipantsCount int64,
	utxoMaxAmount int64,
	utxoMinAmount int64,
	vtxoMaxAmount int64,
	vtxoMinAmount int64,
	allowCSVBlockType bool,
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

	serverSigningKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %s", err)
	}

	dustAmount, err := walletSvc.GetDustAmount(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get dust amount: %s", err)
	}
	var vtxoMinSettlementAmount, vtxoMinOffchainTxAmount = vtxoMinAmount, vtxoMinAmount
	if vtxoMinSettlementAmount < int64(dustAmount) {
		vtxoMinSettlementAmount = int64(dustAmount)
	}
	if vtxoMinOffchainTxAmount == -1 {
		vtxoMinOffchainTxAmount = int64(dustAmount)
	}
	if utxoMinAmount < int64(dustAmount) {
		utxoMinAmount = int64(dustAmount)
	}

	svc := &covenantlessService{
		network:                   network,
		pubkey:                    pubkey,
		vtxoTreeExpiry:            vtxoTreeExpiry,
		roundInterval:             time.Duration(roundInterval) * time.Second,
		unilateralExitDelay:       unilateralExitDelay,
		allowCSVBlockType:         allowCSVBlockType,
		wallet:                    walletSvc,
		repoManager:               repoManager,
		builder:                   builder,
		scanner:                   scanner,
		sweeper:                   newSweeper(walletSvc, repoManager, builder, scheduler, noteUriPrefix),
		txRequests:                newTxRequestsQueue(),
		forfeitTxs:                newForfeitTxsMap(builder),
		offchainTxs:               newOffchainTxsMap(),
		eventsCh:                  make(chan []domain.Event),
		transactionEventsCh:       make(chan TransactionEvent),
		currentRoundLock:          sync.Mutex{},
		treeSigningSessions:       make(map[string]*musigSigningSession),
		boardingExitDelay:         boardingExitDelay,
		serverSigningKey:          serverSigningKey,
		serverSigningPubKey:       serverSigningKey.PubKey(),
		forfeitsBoardingSigsChan:  make(chan struct{}, 1),
		roundMinParticipantsCount: roundMinParticipantsCount,
		roundMaxParticipantsCount: roundMaxParticipantsCount,
		utxoMaxAmount:             utxoMaxAmount,
		utxoMinAmount:             utxoMinAmount,
		vtxoMaxAmount:             vtxoMaxAmount,
		vtxoMinSettlementAmount:   vtxoMinSettlementAmount,
		vtxoMinOffchainTxAmount:   vtxoMinOffchainTxAmount,
		indexerTxEventsCh:         make(chan TransactionEvent),
	}

	repoManager.Events().RegisterEventsHandler(
		domain.RoundTopic, func(events []domain.Event) {
			round := domain.NewRoundFromEvents(events)

			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Errorf("recovered from panic in propagateEvents: %v", r)
					}
				}()

				svc.propagateEvents(round)
			}()

			if !round.IsEnded() {
				return
			}

			spentVtxos := svc.getSpentVtxos(round.TxRequests)
			newVtxos := getNewVtxosFromRound(round)

			go func() {
				svc.transactionEventsCh <- RoundTransactionEvent{
					RoundTxid:      round.Txid,
					SpentVtxos:     spentVtxos,
					SpendableVtxos: newVtxos,
					TxHex:          round.CommitmentTx,
				}
			}()

			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Errorf("recovered from panic in StartWatchingVtxos: %v", r)
					}
				}()

				// nolint
				svc.startWatchingVtxos(newVtxos)
			}()

			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Errorf("recovered from panic in scheduleSweepVtxosForRound: %v", r)
					}
				}()

				svc.scheduleSweepVtxosForRound(round)
			}()
		},
	)

	repoManager.Events().RegisterEventsHandler(
		domain.OffchainTxTopic, func(events []domain.Event) {
			offchainTx := domain.NewOffchainTxFromEvents(events)

			if !offchainTx.IsFinalized() {
				return
			}

			txid, spentVtxoKeys, newVtxos, err := decodeTx(*offchainTx)
			if err != nil {
				log.WithError(err).Warn("failed to decode virtual tx")
				return
			}

			spentVtxos, err := svc.repoManager.Vtxos().GetVtxos(context.Background(), spentVtxoKeys)
			if err != nil {
				log.WithError(err).Warn("failed to get spent vtxos")
				return
			}

			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Errorf("recovered from panic in sendTxEvent: %v", r)
					}
				}()

				svc.transactionEventsCh <- RedeemTransactionEvent{
					RedeemTxid:     txid,
					SpentVtxos:     spentVtxos,
					SpendableVtxos: newVtxos,
					TxHex:          offchainTx.VirtualTx,
				}
			}()

			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Errorf("recovered from panic in startWatchingVtxos: %v", r)
					}
				}()

				// nolint
				svc.startWatchingVtxos(newVtxos)
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
	log.Debug("starting sweeper service...")
	if err := s.sweeper.start(); err != nil {
		return err
	}

	log.Debug("starting app service...")
	go s.start()
	return nil
}

func (s *covenantlessService) Stop() {
	ctx := context.Background()

	s.sweeper.stop()
	// nolint
	vtxos, _ := s.repoManager.Vtxos().GetAllSweepableVtxos(ctx)
	if len(vtxos) > 0 {
		s.stopWatchingVtxos(vtxos)
	}

	// nolint
	s.wallet.Lock(ctx)
	log.Debug("locked wallet")
	s.wallet.Close()
	log.Debug("closed connection to wallet")
	s.repoManager.Close()
	log.Debug("closed connection to db")
	close(s.eventsCh)
}

func (s *covenantlessService) SubmitOffchainTx(
	ctx context.Context, unsignedCheckpoints []string, virtualTx string,
) (signedCheckpoints []string, finalVirtualTx string, virtualTxid string, err error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(virtualTx), true)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to parse redeem tx: %s", err)
	}
	virtualTxid = ptx.UnsignedTx.TxID()

	offchainTx := domain.NewOffchainTx()
	var changes []domain.Event

	defer func() {
		if err != nil {
			change := offchainTx.Fail(err)
			changes = append(changes, change)
		}

		if err := s.repoManager.Events().Save(
			ctx, domain.OffchainTxTopic, virtualTxid, changes,
		); err != nil {
			log.WithError(err).Fatal("failed to save offchain tx events")
		}
	}()

	vtxoRepo := s.repoManager.Vtxos()

	ins := make([]common.VtxoInput, 0)

	checkpointTxs := make(map[string]string)
	checkpointPsbts := make(map[string]*psbt.Packet) // txid -> psbt
	spentVtxoKeys := make([]domain.VtxoKey, 0)
	checkpointTxsByVtxoKey := make(map[domain.VtxoKey]string)
	for _, tx := range unsignedCheckpoints {
		checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to parse checkpoint tx: %s", err)
		}

		if len(checkpointPtx.UnsignedTx.TxIn) < 1 {
			return nil, "", "", fmt.Errorf("invalid checkpoint tx %s", checkpointPtx.UnsignedTx.TxID())
		}

		vtxoKey := domain.VtxoKey{
			Txid: checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String(),
			VOut: checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Index,
		}
		checkpointTxs[checkpointPtx.UnsignedTx.TxID()] = tx
		checkpointPsbts[checkpointPtx.UnsignedTx.TxID()] = checkpointPtx
		checkpointTxsByVtxoKey[vtxoKey] = checkpointPtx.UnsignedTx.TxID()
		spentVtxoKeys = append(spentVtxoKeys, vtxoKey)
	}

	event, err := offchainTx.Request(virtualTxid, virtualTx, checkpointTxs)
	if err != nil {
		return nil, "", "", err
	}
	changes = []domain.Event{event}

	// get all the vtxos inputs
	spentVtxos, err := vtxoRepo.GetVtxos(ctx, spentVtxoKeys)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to get vtxos: %s", err)
	}

	if len(spentVtxos) != len(spentVtxoKeys) {
		return nil, "", "", fmt.Errorf("some vtxos not found")
	}

	if exists, vtxo := s.txRequests.includesAny(spentVtxoKeys); exists {
		return nil, "", "", fmt.Errorf("vtxo %s is already registered for next round", vtxo)
	}

	indexedSpentVtxos := make(map[domain.VtxoKey]domain.Vtxo)
	commitmentTxsByCheckpointTxid := make(map[string]string)
	expiration := int64(math.MaxInt64)
	rootCommitmentTxid := ""
	for _, vtxo := range spentVtxos {
		indexedSpentVtxos[vtxo.VtxoKey] = vtxo
		commitmentTxsByCheckpointTxid[checkpointTxsByVtxoKey[vtxo.VtxoKey]] = vtxo.CommitmentTxid
		if vtxo.ExpireAt < expiration {
			rootCommitmentTxid = vtxo.CommitmentTxid
			expiration = vtxo.ExpireAt
		}
	}

	for _, checkpointPsbt := range checkpointPsbts {
		input := checkpointPsbt.Inputs[0]

		if input.WitnessUtxo == nil {
			return nil, "", "", fmt.Errorf("missing witness utxo")
		}

		if len(input.TaprootLeafScript) == 0 {
			return nil, "", "", fmt.Errorf("missing tapscript leaf")
		}
		if len(input.TaprootLeafScript) != 1 {
			return nil, "", "", fmt.Errorf("expected exactly one taproot leaf script")
		}

		tapscripts, err := tree.GetTaprootTree(input)
		if err != nil {
			return nil, "", "", fmt.Errorf("missing tapscripts: %s", err)
		}

		spendingTapscript := input.TaprootLeafScript[0]

		if spendingTapscript == nil {
			return nil, "", "", fmt.Errorf("no matching tapscript found")
		}

		outpoint := domain.VtxoKey{
			Txid: checkpointPsbt.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String(),
			VOut: checkpointPsbt.UnsignedTx.TxIn[0].PreviousOutPoint.Index,
		}

		vtxo, exists := indexedSpentVtxos[outpoint]
		if !exists {
			return nil, "", "", fmt.Errorf("vtxo not found")
		}

		// make sure we don't use the same vtxo twice
		delete(indexedSpentVtxos, outpoint)

		if vtxo.Spent {
			return nil, "", "", fmt.Errorf("vtxo already spent")
		}

		if vtxo.Redeemed {
			return nil, "", "", fmt.Errorf("vtxo already redeemed")
		}

		if vtxo.Swept {
			return nil, "", "", fmt.Errorf("vtxo already swept")
		}

		if vtxo.IsNote() {
			return nil, "", "", fmt.Errorf("vtxo '%s' is a note, can't be spent in ark transaction", vtxo.String())
		}

		vtxoScript, err := tree.ParseVtxoScript(tapscripts)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to parse vtxo script: %s", err)
		}

		// validate the vtxo script
		if err := vtxoScript.Validate(s.pubkey, s.unilateralExitDelay, s.allowCSVBlockType); err != nil {
			return nil, "", "", fmt.Errorf("invalid vtxo script: %s", err)
		}

		witnessUtxoScript := input.WitnessUtxo.PkScript

		tapKeyFromTapscripts, _, err := vtxoScript.TapTree()
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to get taproot key from vtxo script: %s", err)
		}

		if vtxo.PubKey != hex.EncodeToString(schnorr.SerializePubKey(tapKeyFromTapscripts)) {
			return nil, "", "", fmt.Errorf("vtxo pubkey mismatch")
		}

		pkScriptFromTapscripts, err := common.P2TRScript(tapKeyFromTapscripts)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to get pkscript from taproot key: %s", err)
		}

		if !bytes.Equal(witnessUtxoScript, pkScriptFromTapscripts) {
			return nil, "", "", fmt.Errorf("witness utxo script mismatch")
		}

		vtxoPubkeyBuf, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to decode vtxo pubkey: %s", err)
		}

		vtxoPubkey, err := schnorr.ParsePubKey(vtxoPubkeyBuf)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to parse vtxo pubkey: %s", err)
		}

		// verify witness utxo
		pkscript, err := common.P2TRScript(vtxoPubkey)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to get pkscript: %s", err)
		}

		if !bytes.Equal(input.WitnessUtxo.PkScript, pkscript) {
			return nil, "", "", fmt.Errorf("witness utxo script mismatch")
		}

		if input.WitnessUtxo.Value != int64(vtxo.Amount) {
			return nil, "", "", fmt.Errorf("witness utxo value mismatch")
		}

		// verify forfeit closure script
		closure, err := tree.DecodeClosure(spendingTapscript.Script)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to decode forfeit closure: %s", err)
		}

		var locktime *common.AbsoluteLocktime

		switch c := closure.(type) {
		case *tree.CLTVMultisigClosure:
			locktime = &c.Locktime
		case *tree.MultisigClosure, *tree.ConditionMultisigClosure:
		default:
			return nil, "", "", fmt.Errorf("invalid forfeit closure script %x, cannot verify redeem tx", spendingTapscript.Script)
		}

		if locktime != nil {
			blocktimestamp, err := s.wallet.GetCurrentBlockTime(ctx)
			if err != nil {
				return nil, "", "", fmt.Errorf("failed to get current block time: %s", err)
			}
			if !locktime.IsSeconds() {
				if *locktime > common.AbsoluteLocktime(blocktimestamp.Height) {
					return nil, "", "", fmt.Errorf("forfeit closure is CLTV locked, %d > %d (block time)", *locktime, blocktimestamp.Time)
				}
			} else {
				if *locktime > common.AbsoluteLocktime(blocktimestamp.Time) {
					return nil, "", "", fmt.Errorf("forfeit closure is CLTV locked, %d > %d (block time)", *locktime, blocktimestamp.Time)
				}
			}
		}

		ctrlBlock, err := txscript.ParseControlBlock(spendingTapscript.ControlBlock)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to parse control block: %s", err)
		}

		ins = append(ins, common.VtxoInput{
			Outpoint: &checkpointPsbt.UnsignedTx.TxIn[0].PreviousOutPoint,
			Tapscript: &waddrmgr.Tapscript{
				ControlBlock:   ctrlBlock,
				RevealedScript: spendingTapscript.Script,
			},
			RevealedTapscripts: tapscripts,
			Amount:             int64(vtxo.Amount),
		})
	}

	// iterate over the redeem tx inputs and verify that the user signed a collaborative path
	serverXOnlyPubkey := schnorr.SerializePubKey(s.pubkey)
	for _, input := range ptx.Inputs {
		if len(input.TaprootScriptSpendSig) == 0 {
			return nil, "", "", fmt.Errorf("missing tapscript spend sig")
		}

		hasSig := false

		for _, sig := range input.TaprootScriptSpendSig {
			if !bytes.Equal(sig.XOnlyPubKey, serverXOnlyPubkey) {
				if _, err := schnorr.ParsePubKey(sig.XOnlyPubKey); err != nil {
					return nil, "", "", fmt.Errorf("failed to parse pubkey: %s", err)
				}
				hasSig = true
				break
			}
		}

		if !hasSig {
			return nil, "", "", fmt.Errorf("redeem transaction is not signed")
		}
	}

	dust, err := s.wallet.GetDustAmount(ctx)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to get dust amount: %s", err)
	}

	outputs := make([]*wire.TxOut, 0) // outputs excluding the anchor
	foundAnchor := false
	for outIndex, out := range ptx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, tree.ANCHOR_PKSCRIPT) {
			if foundAnchor {
				return nil, "", "", fmt.Errorf("invalid tx, multiple anchor outputs")
			}
			foundAnchor = true
			continue
		}

		if s.vtxoMaxAmount >= 0 {
			if out.Value > s.vtxoMaxAmount {
				return nil, "", "", fmt.Errorf("output #%d amount is higher than max vtxo amount: %d", outIndex, s.vtxoMaxAmount)
			}
		}
		if out.Value < s.vtxoMinOffchainTxAmount {
			return nil, "", "", fmt.Errorf("output #%d amount is lower than min vtxo amount: %d", outIndex, s.vtxoMinOffchainTxAmount)
		}

		if out.Value < int64(dust) {
			// if the output is below dust limit, it must be using OP_RETURN-style vtxo pkscript
			if !common.IsSubDustScript(out.PkScript) {
				return nil, "", "", fmt.Errorf("output #%d amount is less than dust limit but is not using OP_RETURN output script", outIndex)
			}
		}

		outputs = append(outputs, out)
	}

	if !foundAnchor {
		return nil, "", "", fmt.Errorf("invalid tx, missing anchor output")
	}

	// recompute all txs (checkpoint txs + redeem tx)
	rebuiltVirtualTx, rebuiltCheckpointsTxs, err := tree.BuildOffchainTx(
		ins, outputs,
		&tree.CSVMultisigClosure{
			Locktime: s.unilateralExitDelay,
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{s.pubkey},
			},
		},
	)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to rebuild redeem tx: %s", err)
	}

	// verify the checkpoints txs integrity
	if len(rebuiltCheckpointsTxs) != len(checkpointPsbts) {
		return nil, "", "", fmt.Errorf("invalid number of checkpoint txs")
	}

	for _, rebuiltCheckpointTx := range rebuiltCheckpointsTxs {
		rebuiltTxid := rebuiltCheckpointTx.UnsignedTx.TxID()
		if _, ok := checkpointPsbts[rebuiltTxid]; !ok {
			return nil, "", "", fmt.Errorf("invalid checkpoints")
		}
	}

	// verify the redeem tx integrity
	rebuiltTxid := rebuiltVirtualTx.UnsignedTx.TxID()
	if rebuiltTxid != virtualTxid {
		return nil, "", "", fmt.Errorf("invalid virtual tx")
	}

	// verify the tapscript signatures
	if valid, _, err := s.builder.VerifyTapscriptPartialSigs(virtualTx); err != nil || !valid {
		return nil, "", "", fmt.Errorf("invalid tx signature: %s", err)
	}

	// sign the redeem tx
	signedRedeemTx, err := s.wallet.SignTransactionTapscript(ctx, virtualTx, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to sign redeem tx: %s", err)
	}

	signedCheckpointTxs := make(map[string]string)

	// sign the checkpoint txs
	for _, rebuiltCheckpointTx := range rebuiltCheckpointsTxs {
		unsignedCheckpointTx, err := rebuiltCheckpointTx.B64Encode()
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to encode checkpoint tx: %s", err)
		}
		signedCheckpointTx, err := s.wallet.SignTransactionTapscript(ctx, unsignedCheckpointTx, nil)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to sign checkpoint tx: %s", err)
		}
		signedCheckpointTxs[rebuiltCheckpointTx.UnsignedTx.TxID()] = signedCheckpointTx
	}

	change, err := offchainTx.Accept(
		signedRedeemTx,
		signedCheckpointTxs,
		commitmentTxsByCheckpointTxid,
		rootCommitmentTxid,
		expiration,
	)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to accept offchain tx: %s", err)
	}
	changes = append(changes, change)
	s.offchainTxs.add(*offchainTx)

	finalVirtualTx = signedRedeemTx
	signedCheckpoints = make([]string, 0)
	for _, tx := range signedCheckpointTxs {
		signedCheckpoints = append(signedCheckpoints, tx)
	}

	return signedCheckpoints, finalVirtualTx, virtualTxid, nil
}

func (s *covenantlessService) FinalizeOffchainTx(ctx context.Context, txid string, finalCheckpoints []string) error {
	var (
		changes []domain.Event
		err     error
	)

	offchainTx, exists := s.offchainTxs.get(txid)
	if !exists {
		err = fmt.Errorf("offchain tx: %v not found", txid)
		return err
	}

	defer func() {
		if err != nil {
			change := offchainTx.Fail(err)
			changes = append(changes, change)
		}

		if err = s.repoManager.Events().Save(
			ctx, domain.OffchainTxTopic, txid, changes,
		); err != nil {
			log.WithError(err).Fatal("failed to save offchain tx events")
		}
	}()

	finalCheckpointsTxs := make(map[string]string)
	for _, checkpoint := range finalCheckpoints {
		// verify the tapscript signatures
		valid, checkpointTxid, err := s.builder.VerifyTapscriptPartialSigs(checkpoint)
		if err != nil || !valid {
			return fmt.Errorf("invalid tx signature: %s", err)
		}

		finalCheckpointsTxs[checkpointTxid] = checkpoint
	}

	event, err := offchainTx.Finalize(finalCheckpointsTxs)
	if err != nil {
		return err
	}
	changes = []domain.Event{event}
	s.offchainTxs.remove(txid)

	return nil
}

func (s *covenantlessService) GetBoardingAddress(
	ctx context.Context, userPubkey *secp256k1.PublicKey,
) (address string, scripts []string, err error) {
	vtxoScript := tree.NewDefaultVtxoScript(s.pubkey, userPubkey, s.boardingExitDelay)

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

func (s *covenantlessService) RegisterIntent(ctx context.Context, bip322signature bip322.Signature, message tree.IntentMessage) (string, error) {
	// the vtxo to swap for new ones, require forfeit transactions
	vtxosInputs := make([]domain.Vtxo, 0)
	// the boarding utxos to add in the commitment tx
	boardingInputs := make([]ports.BoardingInput, 0)

	boardingTxs := make(map[string]wire.MsgTx, 0) // txid -> txhex

	outpoints := bip322signature.GetOutpoints()
	if len(outpoints) != len(message.InputTapTrees) {
		return "", fmt.Errorf("number of outpoints and taptrees do not match")
	}

	if message.ValidAt > 0 {
		validAt := time.Unix(message.ValidAt, 0)
		if time.Now().Before(validAt) {
			return "", fmt.Errorf("proof of ownership is not valid yet")
		}
	}

	if message.ExpireAt > 0 {
		expireAt := time.Unix(message.ExpireAt, 0)
		if time.Now().After(expireAt) {
			return "", fmt.Errorf("proof of ownership expired")
		}
	}

	// we need the prevout to verify the BIP0322 signature
	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	for i, outpoint := range outpoints {
		tapTree := message.InputTapTrees[i]
		tapTreeBytes, err := hex.DecodeString(tapTree)
		if err != nil {
			return "", fmt.Errorf("failed to decode taptree: %s", err)
		}

		tapscripts, err := tree.DecodeTapTree(tapTreeBytes)
		if err != nil {
			return "", fmt.Errorf("failed to decode taptree: %s", err)
		}

		vtxoKey := domain.VtxoKey{
			Txid: outpoint.Hash.String(),
			VOut: outpoint.Index,
		}

		if s.offchainTxs.includes(vtxoKey) {
			return "", fmt.Errorf("vtxo %s is currently being spent", vtxoKey.String())
		}

		vtxoScript, err := tree.ParseVtxoScript(tapscripts)
		if err != nil {
			return "", fmt.Errorf("failed to parse vtxo taproot tree: %s", err)
		}

		exitDelay, err := vtxoScript.SmallestExitDelay()
		if err != nil {
			return "", fmt.Errorf("failed to get exit delay: %s", err)
		}

		locktime, disabled := common.BIP68DecodeSequence(bip322signature.TxIn[i+1].Sequence)

		vtxosResult, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.VtxoKey{vtxoKey})
		if err != nil || len(vtxosResult) == 0 {
			// vtxo not found in db, check if it exists on-chain
			if _, ok := boardingTxs[vtxoKey.Txid]; !ok {
				// check if the tx exists and is confirmed
				txhex, err := s.wallet.GetTransaction(ctx, outpoint.Hash.String())
				if err != nil {
					return "", fmt.Errorf("failed to get tx %s: %s", vtxoKey.Txid, err)
				}

				var tx wire.MsgTx
				if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
					return "", fmt.Errorf("failed to deserialize tx %s: %s", vtxoKey.Txid, err)
				}

				confirmed, _, blocktime, err := s.wallet.IsTransactionConfirmed(ctx, vtxoKey.Txid)
				if err != nil {
					return "", fmt.Errorf("failed to check tx %s: %s", vtxoKey.Txid, err)
				}

				if !confirmed {
					return "", fmt.Errorf("tx %s not confirmed", vtxoKey.Txid)
				}

				// validate the vtxo script
				if err := vtxoScript.Validate(s.pubkey, common.RelativeLocktime{
					Type:  s.boardingExitDelay.Type,
					Value: s.boardingExitDelay.Value,
				}, s.allowCSVBlockType); err != nil {
					return "", fmt.Errorf("invalid vtxo script: %s", err)
				}

				// if the exit path is available, forbid registering the boarding utxo
				if time.Unix(blocktime, 0).Add(time.Duration(exitDelay.Seconds()) * time.Second).Before(time.Now()) {
					return "", fmt.Errorf("tx %s expired", vtxoKey.Txid)
				}

				// If the intent is registered using a exit path that contains CSV delay, we want to verify it
				// by shifitng the current "now" in the future of the duration of the smallest exit delay.
				// This way, any exit order guaranteed by the exit path is maintained at intent registration
				if !disabled {
					delta := time.Now().Add(time.Duration(exitDelay.Seconds())*time.Second).Unix() - blocktime
					if diff := locktime.Seconds() - delta; diff > 0 {
						return "", fmt.Errorf("vtxo script can be used for intent registration in %d seconds", diff)
					}
				}

				if s.utxoMaxAmount >= 0 {
					if tx.TxOut[outpoint.Index].Value > s.utxoMaxAmount {
						return "", fmt.Errorf("boarding input amount is higher than max utxo amount:%d", s.utxoMaxAmount)
					}
				}
				if tx.TxOut[outpoint.Index].Value < s.utxoMinAmount {
					return "", fmt.Errorf("boarding input amount is lower than min utxo amount:%d", s.utxoMinAmount)
				}

				boardingTxs[vtxoKey.Txid] = tx
			}

			tx := boardingTxs[vtxoKey.Txid]
			prevout := tx.TxOut[vtxoKey.VOut]
			prevouts[outpoint] = prevout
			input := ports.Input{
				VtxoKey:    vtxoKey,
				Tapscripts: tapscripts,
			}
			boardingInput, err := newBoardingInput(tx, input, s.pubkey, s.boardingExitDelay, s.allowCSVBlockType)
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

		// set the prevout
		pubkeyBytes, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return "", fmt.Errorf("failed to decode script pubkey: %s", err)
		}

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse pubkey: %s", err)
		}

		pkScript, err := common.P2TRScript(pubkey)
		if err != nil {
			return "", fmt.Errorf("failed to create p2tr script: %s", err)
		}

		prevouts[outpoint] = &wire.TxOut{
			Value:    int64(vtxo.Amount),
			PkScript: pkScript,
		}

		// If the intent is registered using a exit path that contains CSV delay, we want to verify it
		// by shifitng the current "now" in the future of the duration of the smallest exit delay.
		// This way, any exit order guaranteed by the exit path is maintained at intent registration
		if !disabled {
			delta := time.Now().Add(time.Duration(exitDelay.Seconds())*time.Second).Unix() - vtxo.CreatedAt
			if diff := locktime.Seconds() - delta; diff > 0 {
				return "", fmt.Errorf("vtxo script can be used for intent registration in %d seconds", diff)
			}
		}

		// We want to validate the taproot tree of an input vtxo only if it requires
		// to be forfeited. Note and swept vtxos can't go onchain, so there's no reason to
		// check if the user is trying to trick us.
		if vtxo.RequiresForfeit() {
			// validate the vtxo script
			if err := vtxoScript.Validate(s.pubkey, s.unilateralExitDelay, s.allowCSVBlockType); err != nil {
				return "", fmt.Errorf("invalid vtxo script: %s", err)
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
				return "", fmt.Errorf(
					"invalid vtxo taproot key: got %x expected %x",
					schnorr.SerializePubKey(tapKey), schnorr.SerializePubKey(expectedTapKey),
				)
			}
		}

		vtxosInputs = append(vtxosInputs, vtxo)
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)

	encodedMessage, err := message.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode message: %s", err)
	}

	if err := bip322signature.Verify(encodedMessage, prevoutFetcher); err != nil {
		return "", fmt.Errorf("invalid BIP0322 proof of funds: %s", err)
	}

	request, err := domain.NewTxRequest(vtxosInputs)
	if err != nil {
		return "", err
	}

	if bip322signature.ContainsOutputs() {
		hasOffChainReceiver := false
		receivers := make([]domain.Receiver, 0)

		for outputIndex, output := range bip322signature.TxOut {
			amount := uint64(output.Value)
			rcv := domain.Receiver{
				Amount: amount,
			}

			isOnchain := false
			for _, index := range message.OnchainOutputIndexes {
				if index == outputIndex {
					isOnchain = true
					break
				}
			}

			if isOnchain {
				if s.utxoMaxAmount >= 0 {
					if amount > uint64(s.utxoMaxAmount) {
						return "", fmt.Errorf("receiver amount is higher than max utxo amount: %d", s.utxoMaxAmount)
					}
				}
				if amount < uint64(s.utxoMinAmount) {
					return "", fmt.Errorf("receiver amount is lower than min utxo amount: %d", s.utxoMinAmount)
				}

				_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript, s.chainParams())
				if err != nil {
					return "", fmt.Errorf("failed to extract pkscript addrs: %s", err)
				}

				if len(addrs) == 0 {
					return "", fmt.Errorf("no onchain address found")
				}

				rcv.OnchainAddress = addrs[0].EncodeAddress()
			} else {
				if s.vtxoMaxAmount >= 0 {
					if amount > uint64(s.vtxoMaxAmount) {
						return "", fmt.Errorf("receiver amount is higher than max vtxo amount: %d", s.vtxoMaxAmount)
					}
				}
				if amount < uint64(s.vtxoMinSettlementAmount) {
					return "", fmt.Errorf("receiver amount is lower than min vtxo amount: %d", s.vtxoMinSettlementAmount)
				}

				hasOffChainReceiver = true
				rcv.PubKey = hex.EncodeToString(output.PkScript[2:])
			}

			receivers = append(receivers, rcv)
		}

		if hasOffChainReceiver {
			if len(message.CosignersPublicKeys) == 0 {
				return "", fmt.Errorf("musig2 data is required for offchain receivers")
			}

			// check if the server pubkey has been set as cosigner
			serverPubKeyHex := hex.EncodeToString(s.serverSigningPubKey.SerializeCompressed())
			for _, pubkey := range message.CosignersPublicKeys {
				if pubkey == serverPubKeyHex {
					return "", fmt.Errorf("server pubkey already in musig2 data")
				}
			}
		}

		if err := request.AddReceivers(receivers); err != nil {
			return "", err
		}
	}

	if err := s.txRequests.push(*request, boardingInputs, message.CosignersPublicKeys); err != nil {
		return "", err
	}

	return request.Id, nil
}

func (s *covenantlessService) SpendVtxos(ctx context.Context, inputs []ports.Input) (string, error) {
	vtxosInputs := make([]domain.Vtxo, 0)
	boardingInputs := make([]ports.BoardingInput, 0)

	now := time.Now().Unix()

	boardingTxs := make(map[string]wire.MsgTx, 0) // txid -> txhex

	for _, input := range inputs {
		if s.offchainTxs.includes(input.VtxoKey) {
			return "", fmt.Errorf("vtxo %s is currently being spent", input.String())
		}

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

				vtxoScript, err := tree.ParseVtxoScript(input.Tapscripts)
				if err != nil {
					return "", fmt.Errorf("failed to parse boarding utxo taproot tree: %s", err)
				}

				// validate the vtxo script
				if err := vtxoScript.Validate(s.pubkey, s.boardingExitDelay, s.allowCSVBlockType); err != nil {
					return "", fmt.Errorf("invalid vtxo script: %s", err)
				}

				exitDelay, err := vtxoScript.SmallestExitDelay()
				if err != nil {
					return "", fmt.Errorf("failed to get exit delay: %s", err)
				}

				// if the exit path is available, forbid registering the boarding utxo
				if blocktime+exitDelay.Seconds() < now {
					return "", fmt.Errorf("tx %s expired", input.Txid)
				}

				if s.utxoMaxAmount >= 0 {
					if tx.TxOut[input.VOut].Value > s.utxoMaxAmount {
						return "", fmt.Errorf("boarding input amount is higher than max utxo amount:%d", s.utxoMaxAmount)
					}
				}
				if tx.TxOut[input.VOut].Value < s.utxoMinAmount {
					return "", fmt.Errorf("boarding input amount is lower than min utxo amount:%d", s.utxoMinAmount)
				}

				boardingTxs[input.Txid] = tx
			}

			tx := boardingTxs[input.Txid]
			boardingInput, err := newBoardingInput(tx, input, s.pubkey, s.boardingExitDelay, s.allowCSVBlockType)
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
			return "", fmt.Errorf("failed to parse vtxo taproot tree: %s", err)
		}

		// validate the vtxo script
		if err := vtxoScript.Validate(s.pubkey, s.unilateralExitDelay, s.allowCSVBlockType); err != nil {
			return "", fmt.Errorf("invalid vtxo script: %s", err)
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
			return "", fmt.Errorf(
				"invalid vtxo taproot key: got %x expected %x",
				schnorr.SerializePubKey(tapKey), schnorr.SerializePubKey(expectedTapKey),
			)
		}

		vtxosInputs = append(vtxosInputs, vtxo)
	}

	request, err := domain.NewTxRequest(vtxosInputs)
	if err != nil {
		return "", err
	}

	if err := s.txRequests.push(*request, boardingInputs, nil); err != nil {
		return "", err
	}

	return request.Id, nil
}

func (s *covenantlessService) ConfirmRegistration(ctx context.Context, intentId string) error {
	if s.confirmationSession == nil {
		return fmt.Errorf("confirmation session not started")
	}

	return s.confirmationSession.confirm(intentId)
}

func (s *covenantlessService) ClaimVtxos(ctx context.Context, creds string, receivers []domain.Receiver, cosignersPublicKeys []string) error {
	// Check credentials
	request, ok := s.txRequests.view(creds)
	if !ok {
		return fmt.Errorf("invalid credentials")
	}

	hasOffChainReceiver := false

	for _, rcv := range receivers {
		if s.vtxoMaxAmount >= 0 {
			if rcv.Amount > uint64(s.vtxoMaxAmount) {
				return fmt.Errorf("receiver amount is higher than max vtxo amount: %d", s.vtxoMaxAmount)
			}
		}
		if s.vtxoMinSettlementAmount >= 0 {
			if rcv.Amount < uint64(s.vtxoMinSettlementAmount) {
				return fmt.Errorf("receiver amount is lower than min vtxo amount: %d", s.vtxoMinSettlementAmount)
			}
		}

		if !rcv.IsOnchain() {
			hasOffChainReceiver = true
		}
	}

	if hasOffChainReceiver {
		if len(cosignersPublicKeys) == 0 {
			return fmt.Errorf("musig2 data is required for offchain receivers")
		}

		// check if the server pubkey has been set as cosigner
		serverPubKeyHex := hex.EncodeToString(s.serverSigningPubKey.SerializeCompressed())
		for _, pubkey := range cosignersPublicKeys {
			if pubkey == serverPubKeyHex {
				return fmt.Errorf("server pubkey already in musig2 data")
			}
		}
	}

	if err := request.AddReceivers(receivers); err != nil {
		return err
	}

	return s.txRequests.update(*request, cosignersPublicKeys)
}

func (s *covenantlessService) SignVtxos(ctx context.Context, forfeitTxs []string) error {
	if len(forfeitTxs) <= 0 {
		return nil
	}

	if err := s.forfeitTxs.sign(forfeitTxs); err != nil {
		return err
	}

	go s.checkForfeitsAndBoardingSigsSent()

	return nil
}

func (s *covenantlessService) SignRoundTx(ctx context.Context, signedRoundTx string) error {
	numSignedInputs, err := s.builder.CountSignedTaprootInputs(signedRoundTx)
	if err != nil {
		return fmt.Errorf("failed to count number of signed boarding inputs: %s", err)
	}
	if numSignedInputs == 0 {
		return nil
	}

	s.currentRoundLock.Lock()
	defer s.currentRoundLock.Unlock()
	currentRound := s.currentRound

	combined, err := s.builder.VerifyAndCombinePartialTx(currentRound.CommitmentTx, signedRoundTx)
	if err != nil {
		return fmt.Errorf("failed to verify and combine partial tx: %s", err)
	}

	s.currentRound.CommitmentTx = combined

	go s.checkForfeitsAndBoardingSigsSent()

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

	return s.repoManager.Vtxos().GetAllNonRedeemedVtxos(ctx, pubkey)
}

func (s *covenantlessService) GetEventsChannel(ctx context.Context) <-chan []domain.Event {
	return s.eventsCh
}

func (s *covenantlessService) GetTransactionEventsChannel(ctx context.Context) <-chan TransactionEvent {
	return s.transactionEventsCh
}

// TODO remove this in v7
func (s *covenantlessService) GetIndexerTxChannel(ctx context.Context) <-chan TransactionEvent {
	return s.indexerTxEventsCh
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
		BoardingExitDelay:   int64(s.boardingExitDelay.Value),
		RoundInterval:       int64(s.roundInterval.Seconds()),
		Network:             s.network.Name,
		Dust:                dust,
		ForfeitAddress:      forfeitAddr,
		NextMarketHour: &NextMarketHour{
			StartTime:     marketHourNextStart,
			EndTime:       marketHourNextEnd,
			Period:        marketHourConfig.Period,
			RoundInterval: marketHourConfig.RoundInterval,
		},
		UtxoMinAmount: s.utxoMinAmount,
		UtxoMaxAmount: s.utxoMaxAmount,
		VtxoMinAmount: s.vtxoMinSettlementAmount,
		VtxoMaxAmount: s.vtxoMaxAmount,
	}, nil
}

func (s *covenantlessService) GetTxRequestQueue(
	ctx context.Context, requestIds ...string,
) ([]TxRequestInfo, error) {
	requests, err := s.txRequests.viewAll(requestIds)
	if err != nil {
		return nil, err
	}

	txReqsInfo := make([]TxRequestInfo, 0, len(requests))
	for _, request := range requests {
		cosigners := request.cosignersPublicKeys

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

		txReqsInfo = append(txReqsInfo, TxRequestInfo{
			Id:             request.Id,
			CreatedAt:      request.timestamp,
			Receivers:      receivers,
			Inputs:         request.Inputs,
			BoardingInputs: request.boardingInputs,
			Cosigners:      cosigners,
		})
	}

	return txReqsInfo, nil
}

func (s *covenantlessService) DeleteTxRequests(
	ctx context.Context, requestIds ...string,
) error {
	if len(requestIds) == 0 {
		return s.txRequests.deleteAll()
	}
	return s.txRequests.delete(requestIds)
}

// DeleteTxRequestsByProof deletes transaction requests matching the BIP322 proof.
func (s *covenantlessService) DeleteTxRequestsByProof(
	ctx context.Context, sig bip322.Signature, message tree.DeleteIntentMessage,
) error {
	if message.ExpireAt > 0 {
		expireAt := time.Unix(message.ExpireAt, 0)
		if time.Now().After(expireAt) {
			return fmt.Errorf("proof of ownership expired")
		}
	}

	outpoints := sig.GetOutpoints()

	boardingTxs := make(map[string]wire.MsgTx)
	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	for _, outpoint := range outpoints {
		vtxoKey := domain.VtxoKey{
			Txid: outpoint.Hash.String(),
			VOut: outpoint.Index,
		}

		vtxosResult, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.VtxoKey{vtxoKey})
		if err != nil || len(vtxosResult) == 0 {
			if _, ok := boardingTxs[vtxoKey.Txid]; !ok {
				txhex, err := s.wallet.GetTransaction(ctx, outpoint.Hash.String())
				if err != nil {
					return fmt.Errorf("failed to get tx %s: %s", vtxoKey.Txid, err)
				}

				var tx wire.MsgTx
				if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
					return fmt.Errorf("failed to deserialize tx %s: %s", vtxoKey.Txid, err)
				}

				boardingTxs[vtxoKey.Txid] = tx
			}

			tx := boardingTxs[vtxoKey.Txid]
			prevout := tx.TxOut[vtxoKey.VOut]
			prevouts[outpoint] = prevout
			continue
		}

		vtxo := vtxosResult[0]
		pubkeyBytes, err := hex.DecodeString(vtxo.PubKey)
		if err != nil {
			return fmt.Errorf("failed to decode script pubkey: %s", err)
		}

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse pubkey: %s", err)
		}

		pkScript, err := common.P2TRScript(pubkey)
		if err != nil {
			return fmt.Errorf("failed to create p2tr script: %s", err)
		}

		prevouts[outpoint] = &wire.TxOut{
			Value:    int64(vtxo.Amount),
			PkScript: pkScript,
		}
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	encodedMessage, err := message.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode message: %s", err)
	}

	if err := sig.Verify(encodedMessage, prevoutFetcher); err != nil {
		return fmt.Errorf("failed to verify signature: %s", err)
	}

	allRequests, err := s.txRequests.viewAll(nil)
	if err != nil {
		return err
	}

	idsToDeleteMap := make(map[string]struct{})
	for _, req := range allRequests {
		for _, in := range req.Inputs {
			for _, op := range outpoints {
				if in.Txid == op.Hash.String() && in.VOut == op.Index {
					if _, ok := idsToDeleteMap[req.Id]; !ok {
						idsToDeleteMap[req.Id] = struct{}{}
					}
				}
			}
		}
	}

	if len(idsToDeleteMap) == 0 {
		return fmt.Errorf("no matching tx requests found for BIP322 proof")
	}

	idsToDelete := make([]string, 0, len(idsToDeleteMap))
	for id := range idsToDeleteMap {
		idsToDelete = append(idsToDelete, id)
	}

	if len(idsToDelete) == 0 {
		return fmt.Errorf("no matching tx requests found for BIP322 proof")
	}

	return s.txRequests.delete(idsToDelete)
}

func (s *covenantlessService) RegisterCosignerNonces(
	ctx context.Context, roundID string, pubkey *secp256k1.PublicKey, encodedNonces string,
) error {
	session, ok := s.treeSigningSessions[roundID]
	if !ok {
		return fmt.Errorf(`signing session not found for round "%s"`, roundID)
	}

	userPubkey := hex.EncodeToString(pubkey.SerializeCompressed())
	if _, ok := session.cosigners[userPubkey]; !ok {
		return fmt.Errorf(`cosigner %s not found for round "%s"`, userPubkey, roundID)
	}

	nonces, err := tree.DecodeNonces(hex.NewDecoder(strings.NewReader(encodedNonces)))
	if err != nil {
		return fmt.Errorf("failed to decode nonces: %s", err)
	}

	go func(session *musigSigningSession) {
		session.lock.Lock()
		defer session.lock.Unlock()

		if _, ok := session.nonces[pubkey]; ok {
			return // skip if we already have nonces for this pubkey
		}

		session.nonces[pubkey] = nonces

		if len(session.nonces) == session.nbCosigners-1 { // exclude the server
			go func() {
				session.nonceDoneC <- struct{}{}
			}()
		}
	}(session)

	return nil
}

func (s *covenantlessService) RegisterCosignerSignatures(
	ctx context.Context, roundID string, pubkey *secp256k1.PublicKey, encodedSignatures string,
) error {
	session, ok := s.treeSigningSessions[roundID]
	if !ok {
		return fmt.Errorf(`signing session not found for round "%s"`, roundID)
	}

	userPubkey := hex.EncodeToString(pubkey.SerializeCompressed())
	if _, ok := session.cosigners[userPubkey]; !ok {
		return fmt.Errorf(`cosigner %s not found for round "%s"`, userPubkey, roundID)
	}

	signatures, err := tree.DecodeSignatures(hex.NewDecoder(strings.NewReader(encodedSignatures)))
	if err != nil {
		return fmt.Errorf("failed to decode signatures: %s", err)
	}

	go func(session *musigSigningSession) {
		session.lock.Lock()
		defer session.lock.Unlock()

		if _, ok := session.signatures[pubkey]; ok {
			return // skip if we already have signatures for this pubkey
		}

		session.signatures[pubkey] = signatures

		if len(session.signatures) == session.nbCosigners-1 { // exclude the server
			go func() {
				session.sigDoneC <- struct{}{}
			}()
		}
	}(session)

	return nil
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

func (s *covenantlessService) start() {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("recovered from panic in start: %v", r)
		}
	}()

	s.startRound()
}

func (s *covenantlessService) startRound() {
	// reset the forfeit txs map to avoid polluting the next batch of forfeits transactions
	s.forfeitTxs.reset()

	round := domain.NewRound()
	//nolint:all
	round.StartRegistration()
	s.currentRound = round

	close(s.forfeitsBoardingSigsChan)
	s.forfeitsBoardingSigsChan = make(chan struct{}, 1)

	defer func() {
		roundTiming := newRoundTiming(s.roundInterval)
		<-time.After(roundTiming.registrationDuration())
		s.startConfirmation(roundTiming)
	}()

	log.Debugf("started registration stage for new round: %s", round.Id)
}

func (s *covenantlessService) startConfirmation(roundTiming roundTiming) {
	round := s.getCurrentRound()
	log.Debugf("started confirmation stage for round: %s", round.Id)

	ctx := context.Background()

	var registeredRequests []timedTxRequest
	roundAborted := false

	defer func() {
		s.confirmationSession = nil

		if roundAborted {
			s.startRound()
			return
		}

		if err := s.saveEvents(ctx, round.Id, round.Events()); err != nil {
			log.WithError(err).Warn("failed to store new round events")
		}

		if round.IsFailed() {
			s.txRequests.deleteVtxos()
			s.startRound()
			return
		}

		s.startFinalization(roundTiming, registeredRequests)
	}()

	// TODO: understand how many tx requests must be popped from the queue and actually registered for the round
	num := s.txRequests.len()
	if num < s.roundMinParticipantsCount {
		roundAborted = true
		err := fmt.Errorf("not enough tx requests registered %d/%d", num, s.roundMinParticipantsCount)
		log.WithError(err).Debugf("round %s aborted", round.Id)
		return
	}
	if num > s.roundMaxParticipantsCount {
		num = s.roundMaxParticipantsCount
	}

	availableBalance, _, err := s.wallet.MainAccountBalance(ctx)
	if err != nil {
		round.Fail(fmt.Errorf("failed to get main account balance: %s", err))
		log.WithError(err).Warn("failed to get main account balance")
		return
	}

	forfeitAddress, err := s.wallet.GetForfeitAddress(ctx)
	if err != nil {
		round.Fail(fmt.Errorf("failed to get forfeit address: %s", err))
		log.WithError(err).Warn("failed to get forfeit address")
		return
	}

	// TODO take into account available liquidity
	requests := s.txRequests.pop(num)

	totAmount := uint64(0)
	for _, request := range requests {
		totAmount += request.TotalOutputAmount()
	}
	if availableBalance <= totAmount {
		err := fmt.Errorf("not enough liquidity")
		round.Fail(err)
		log.WithError(err).Debugf("round %s aborted, balance: %d", round.Id, availableBalance)
		return
	}

	s.propagateBatchStartedEvent(requests, forfeitAddress)

	confirmedRequests := make([]timedTxRequest, 0)
	notConfirmedRequests := make([]timedTxRequest, 0)

	select {
	case <-time.After(roundTiming.confirmationDuration()):
		for _, req := range requests {
			if s.confirmationSession.intentsHashes[req.hashID()] {
				confirmedRequests = append(confirmedRequests, req)
				continue
			}
			notConfirmedRequests = append(notConfirmedRequests, req)
		}
	case <-s.confirmationSession.confirmedC:
		confirmedRequests = requests
	}

	close(s.confirmationSession.confirmedC)

	repushToQueue := notConfirmedRequests
	if int64(len(confirmedRequests)) < s.roundMinParticipantsCount {
		repushToQueue = append(repushToQueue, confirmedRequests...)
		confirmedRequests = make([]timedTxRequest, 0)
	}

	// register confirmed requests if we have enough participants
	if len(confirmedRequests) > 0 {
		txRequests := make([]domain.TxRequest, 0, len(confirmedRequests))
		numOfBoardingInputs := 0
		for _, req := range confirmedRequests {
			txRequests = append(txRequests, req.TxRequest)
			numOfBoardingInputs += len(req.boardingInputs)
		}

		s.numOfBoardingInputsMtx.Lock()
		s.numOfBoardingInputs = numOfBoardingInputs
		s.numOfBoardingInputsMtx.Unlock()

		if _, err := round.RegisterTxRequests(txRequests); err != nil {
			round.Fail(fmt.Errorf("failed to register tx requests: %s", err))
			log.WithError(err).Warn("failed to register tx requests")
			return
		}
		registeredRequests = confirmedRequests
	}

	if len(repushToQueue) > 0 {
		for _, req := range repushToQueue {
			if err := s.txRequests.push(req.TxRequest, req.boardingInputs, req.cosignersPublicKeys); err != nil {
				log.WithError(err).Warn("failed to re-push requests to the queue")
				continue
			}
		}

		// make the round fail if we don't register this round
		if len(confirmedRequests) == 0 {
			round.Fail(fmt.Errorf("not enough participants confirmed"))
			log.Warn("not enough participants confirmed")
			return
		}
	}
}

func (s *covenantlessService) startFinalization(roundTiming roundTiming, requests []timedTxRequest) {
	round := s.getCurrentRound()
	log.Debugf("started finalization stage for round: %s", round.Id)
	ctx := context.Background()

	thirdOfRemainingDuration := roundTiming.finalizationDuration()

	defer func() {
		delete(s.treeSigningSessions, round.Id)

		if err := s.saveEvents(ctx, round.Id, round.Events()); err != nil {
			log.WithError(err).Warn("failed to store new round events")
		}

		if round.IsFailed() {
			s.txRequests.deleteVtxos()
			s.startRound()
			return
		}

		s.finalizeRound(roundTiming)
	}()

	if round.IsFailed() {
		return
	}

	connectorAddresses, err := s.repoManager.Rounds().GetSweptRoundsConnectorAddress(ctx)
	if err != nil {
		round.Fail(fmt.Errorf("failed to retrieve swept rounds: %s", err))
		log.WithError(err).Warn("failed to retrieve swept rounds")
		return
	}

	serverPubKeyHex := hex.EncodeToString(s.serverSigningPubKey.SerializeCompressed())

	txRequests := make([]domain.TxRequest, 0, len(requests))
	boardingInputs := make([]ports.BoardingInput, 0)
	cosignersPublicKeys := make([][]string, 0)
	uniqueSignerPubkeys := make(map[string]struct{})

	for _, req := range requests {
		txRequests = append(txRequests, req.TxRequest)
		boardingInputs = append(boardingInputs, req.boardingInputs...)
		for _, pubkey := range req.cosignersPublicKeys {
			uniqueSignerPubkeys[pubkey] = struct{}{}
		}

		cosignersPublicKeys = append(cosignersPublicKeys, append(req.cosignersPublicKeys, serverPubKeyHex))
	}

	log.Debugf("building tx for round %s", round.Id)
	unsignedRoundTx, vtxoTree, connectorAddress, connectors, err := s.builder.BuildRoundTx(
		s.pubkey, txRequests, boardingInputs, connectorAddresses, cosignersPublicKeys,
	)
	if err != nil {
		round.Fail(fmt.Errorf("failed to create round tx: %s", err))
		log.WithError(err).Warn("failed to create round tx")
		return
	}
	log.Debugf("round tx created for round %s", round.Id)

	if err := s.forfeitTxs.init(connectors, txRequests); err != nil {
		round.Fail(fmt.Errorf("failed to initialize forfeit txs: %s", err))
		log.WithError(err).Warn("failed to initialize forfeit txs")
		return
	}

	if len(vtxoTree) > 0 {
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

		coordinator, err := tree.NewTreeCoordinatorSession(sharedOutputAmount, vtxoTree, root.CloneBytes())
		if err != nil {
			round.Fail(fmt.Errorf("failed to create tree coordinator: %s", err))
			log.WithError(err).Warn("failed to create tree coordinator")
			return
		}

		serverSignerSession := tree.NewTreeSignerSession(s.serverSigningKey)
		if err := serverSignerSession.Init(root.CloneBytes(), sharedOutputAmount, vtxoTree); err != nil {
			round.Fail(fmt.Errorf("failed to create tree signer session: %s", err))
			log.WithError(err).Warn("failed to create tree signer session")
			return
		}

		nonces, err := serverSignerSession.GetNonces()
		if err != nil {
			round.Fail(fmt.Errorf("failed to get nonces: %s", err))
			log.WithError(err).Warn("failed to get nonces")
			return
		}

		coordinator.AddNonce(s.serverSigningPubKey, nonces)

		signingSession := newMusigSigningSession(uniqueSignerPubkeys)
		s.treeSigningSessions[round.Id] = signingSession

		log.Debugf("signing session created for round %s with %d signers", round.Id, len(uniqueSignerPubkeys))

		s.currentRound.Txid = unsignedPsbt.UnsignedTx.TxHash().String()
		s.currentRound.CommitmentTx = unsignedRoundTx

		// send back the unsigned tree & all cosigners pubkeys
		listOfCosignersPubkeys := make([]string, 0, len(uniqueSignerPubkeys))
		for pubkey := range uniqueSignerPubkeys {
			listOfCosignersPubkeys = append(listOfCosignersPubkeys, pubkey)
		}

		s.propagateRoundSigningStartedEvent(vtxoTree, listOfCosignersPubkeys)

		select {
		case <-time.After(thirdOfRemainingDuration):
			err := fmt.Errorf(
				"musig2 signing session timed out (nonce collection), collected %d/%d nonces",
				len(signingSession.nonces), len(uniqueSignerPubkeys),
			)
			round.Fail(err)
			log.Warn(err)
			return
		case <-signingSession.nonceDoneC:
			for pubkey, nonce := range signingSession.nonces {
				coordinator.AddNonce(pubkey, nonce)
			}
		}

		log.Debugf("nonces collected for round %s", round.Id)

		aggregatedNonces, err := coordinator.AggregateNonces()
		if err != nil {
			round.Fail(fmt.Errorf("failed to aggregate nonces: %s", err))
			log.WithError(err).Warn("failed to aggregate nonces")
			return
		}

		log.Debugf("nonces aggregated for round %s", round.Id)

		serverSignerSession.SetAggregatedNonces(aggregatedNonces)

		// send the combined nonces to the clients
		s.propagateRoundSigningNoncesGeneratedEvent(aggregatedNonces)

		// sign the tree as server
		serverTreeSigs, err := serverSignerSession.Sign()
		if err != nil {
			round.Fail(fmt.Errorf("failed to sign tree: %s", err))
			log.WithError(err).Warn("failed to sign tree")
			return
		}
		coordinator.AddSignatures(s.serverSigningPubKey, serverTreeSigs)

		log.Debugf("tree signed by us for round %s", round.Id)

		log.Debugf("waiting for cosigners to sign the tree")

		select {
		case <-time.After(thirdOfRemainingDuration):
			err := fmt.Errorf(
				"musig2 signing session timed out (signatures collection), collected %d/%d signatures",
				len(signingSession.signatures), len(uniqueSignerPubkeys),
			)
			round.Fail(err)
			log.Warn(err)
			return
		case <-signingSession.sigDoneC:
			for pubkey, sig := range signingSession.signatures {
				coordinator.AddSignatures(pubkey, sig)
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

	_, err = round.StartFinalization(
		connectorAddress, connectors, vtxoTree, s.currentRound.Txid, s.currentRound.CommitmentTx,
		s.forfeitTxs.connectorsIndex, s.vtxoTreeExpiry.Seconds(),
	)
	if err != nil {
		round.Fail(fmt.Errorf("failed to start finalization: %s", err))
		log.WithError(err).Warn("failed to start finalization")
		return
	}

	log.Debugf("started finalization stage for round: %s", round.Id)
}

func (s *covenantlessService) finalizeRound(roundTiming roundTiming) {
	defer s.startRound()

	ctx := context.Background()
	round := s.getCurrentRound()
	defer s.txRequests.deleteVtxos()

	if round.IsFailed() {
		return
	}

	var changes []domain.Event
	defer func() {
		if err := s.saveEvents(ctx, round.Id, changes); err != nil {
			log.WithError(err).Warn("failed to store new round events")
			return
		}
	}()

	roundTx, err := psbt.NewFromRawBytes(strings.NewReader(round.CommitmentTx), true)
	if err != nil {
		log.Debugf("failed to parse round tx: %s", round.CommitmentTx)
		changes = round.Fail(fmt.Errorf("failed to parse round tx: %s", err))
		log.WithError(err).Warn("failed to parse round tx")
		return
	}
	includesBoardingInputs := false
	for _, in := range roundTx.Inputs {
		// TODO: this is ok as long as the server doesn't use taproot address too!
		// We need to find a better way to understand if an in input is ours or if
		// it's a boarding one.
		scriptType := txscript.GetScriptClass(in.WitnessUtxo.PkScript)
		if scriptType == txscript.WitnessV1TaprootTy {
			includesBoardingInputs = true
			break
		}
	}

	txToSign := round.CommitmentTx
	forfeitTxs := make([]domain.ForfeitTx, 0)

	if len(s.forfeitTxs.forfeitTxs) > 0 || includesBoardingInputs {
		remainingTime := roundTiming.remainingDuration()
		select {
		case <-s.forfeitsBoardingSigsChan:
			log.Debug("all forfeit txs and boarding inputs signatures have been sent")
		case <-time.After(remainingTime):
			log.Debug("timeout waiting for forfeit txs and boarding inputs signatures")
		}

		roundTx, err := psbt.NewFromRawBytes(strings.NewReader(round.CommitmentTx), true)
		if err != nil {
			log.Debugf("failed to parse round tx: %s", round.CommitmentTx)
			changes = round.Fail(fmt.Errorf("failed to parse round tx: %s", err))
			log.WithError(err).Warn("failed to parse round tx")
			return
		}
		txToSign = round.CommitmentTx

		forfeitTxList, err := s.forfeitTxs.pop()
		if err != nil {
			changes = round.Fail(fmt.Errorf("failed to finalize round: %s", err))
			log.WithError(err).Warn("failed to finalize round")
			return
		}

		if err := s.verifyForfeitTxsSigs(forfeitTxList); err != nil {
			changes = round.Fail(err)
			log.WithError(err).Warn("failed to validate forfeit txs")
			return
		}

		boardingInputsIndexes := make([]int, 0)
		for i, in := range roundTx.Inputs {
			if len(in.TaprootLeafScript) > 0 {
				if len(in.TaprootScriptSpendSig) == 0 {
					err = fmt.Errorf("missing tapscript spend sig for input %d", i)
					changes = round.Fail(err)
					log.WithError(err).Warn("missing boarding sig")
					return
				}

				boardingInputsIndexes = append(boardingInputsIndexes, i)
			}
		}

		if len(boardingInputsIndexes) > 0 {
			txToSign, err = s.wallet.SignTransactionTapscript(ctx, txToSign, boardingInputsIndexes)
			if err != nil {
				changes = round.Fail(fmt.Errorf("failed to sign round tx: %s", err))
				log.WithError(err).Warn("failed to sign round tx")
				return
			}
		}

		for _, tx := range forfeitTxList {
			// nolint:all
			ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
			forfeitTxid := ptx.UnsignedTx.TxHash().String()
			forfeitTxs = append(forfeitTxs, domain.ForfeitTx{
				Txid: forfeitTxid,
				Tx:   tx,
			})
		}
	}

	log.Debugf("signing transaction %s\n", round.Id)

	signedRoundTx, err := s.wallet.SignTransaction(ctx, txToSign, true)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to sign round tx: %s", err))
		log.WithError(err).Warn("failed to sign round tx")
		return
	}

	if _, err := s.wallet.BroadcastTransaction(ctx, signedRoundTx); err != nil {
		changes = round.Fail(fmt.Errorf("failed to broadcast round tx: %s", err))
		return
	}

	changes, err = round.EndFinalization(forfeitTxs, signedRoundTx)
	if err != nil {
		changes = round.Fail(fmt.Errorf("failed to finalize round: %s", err))
		log.WithError(err).Warn("failed to finalize round")
		return
	}

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
									// log the stack trace
									log.Errorf("stack trace: %s", string(debug.Stack()))
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

func (s *covenantlessService) propagateEvents(round *domain.Round) {
	lastEvent := round.Events()[len(round.Events())-1]
	events := make([]domain.Event, 0)
	switch ev := lastEvent.(type) {
	// RoundFinalizationStarted event must be handled differently
	// because it contains the vtxoTree and connectorsTree
	// and we need to propagate them in specific BatchTree events
	case domain.RoundFinalizationStarted:
		events = append(
			events,
			batchTreeSignatureEvents(ev.VtxoTree, 0, round.Id)...,
		)
		events = append(
			events,
			batchTreeEvents(ev.Connectors, 1, round.Id)...,
		)
	case domain.RoundFinalized:
		lastEvent = RoundFinalized{lastEvent.(domain.RoundFinalized), round.Txid}
	}

	events = append(events, lastEvent)
	s.eventsCh <- events
}

func (s *covenantlessService) propagateBatchStartedEvent(requests []timedTxRequest, forfeitAddr string) {
	intentIdsHashes := make([][32]byte, 0, len(requests))
	for _, req := range requests {
		intentIdsHashes = append(intentIdsHashes, req.hashID())
	}

	s.confirmationSession = newConfirmationSession(intentIdsHashes)

	ev := BatchStarted{
		RoundEvent: domain.RoundEvent{
			Id:   s.currentRound.Id,
			Type: domain.EventTypeUndefined,
		},
		IntentIdsHashes: intentIdsHashes,
		BatchExpiry:     s.vtxoTreeExpiry.Value,
		ForfeitAddress:  forfeitAddr,
	}
	s.eventsCh <- []domain.Event{ev}
}

func (s *covenantlessService) propagateRoundSigningStartedEvent(unsignedVtxoTree tree.TxTree, cosignersPubkeys []string) {
	events := append(
		batchTreeEvents(unsignedVtxoTree, 0, s.currentRound.Id),
		RoundSigningStarted{
			RoundEvent: domain.RoundEvent{
				Id:   s.currentRound.Id,
				Type: domain.EventTypeUndefined,
			},
			UnsignedRoundTx:  s.currentRound.CommitmentTx,
			CosignersPubkeys: cosignersPubkeys,
		},
	)

	s.eventsCh <- events
}

func (s *covenantlessService) propagateRoundSigningNoncesGeneratedEvent(combinedNonces tree.TreeNonces) {
	ev := RoundSigningNoncesGenerated{
		RoundEvent: domain.RoundEvent{
			Id:   s.currentRound.Id,
			Type: domain.EventTypeUndefined,
		},
		Nonces: combinedNonces,
	}

	s.eventsCh <- []domain.Event{ev}
}

func (s *covenantlessService) scheduleSweepVtxosForRound(round *domain.Round) {
	// Schedule the sweeping procedure only for completed round.
	if !round.IsEnded() {
		return
	}

	expirationTimestamp := s.sweeper.scheduler.AddNow(int64(s.vtxoTreeExpiry.Value))

	log.Debugf("round %s sweeping scheduled at %s", round.Txid, fancyTime(expirationTimestamp, s.sweeper.scheduler.Unit()))

	if err := s.sweeper.schedule(expirationTimestamp, round.Txid, round.VtxoTree); err != nil {
		log.WithError(err).Warn("failed to schedule sweep tx")
	}
}

func (s *covenantlessService) checkForfeitsAndBoardingSigsSent() {
	currentRound := s.getCurrentRound()

	roundTx, _ := psbt.NewFromRawBytes(strings.NewReader(currentRound.CommitmentTx), true)
	numOfInputsSigned := 0
	for _, v := range roundTx.Inputs {
		if len(v.TaprootScriptSpendSig) > 0 {
			if len(v.TaprootScriptSpendSig[0].Signature) > 0 {
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
		}
	}
}

func (s *covenantlessService) getSpentVtxos(requests map[string]domain.TxRequest) []domain.Vtxo {
	outpoints := getSpentVtxos(requests)
	vtxos, _ := s.repoManager.Vtxos().GetVtxos(context.Background(), outpoints)
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

	unsweptRounds, err := s.repoManager.Rounds().GetUnsweptRoundsTxid(ctx)
	if err != nil {
		return err
	}

	vtxos := make([]domain.Vtxo, 0)
	for _, txid := range unsweptRounds {
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
	dustLimit, err := s.wallet.GetDustAmount(context.Background())
	if err != nil {
		return nil, err
	}

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

		var script []byte

		if vtxo.Amount < dustLimit {
			script, err = common.SubDustScript(vtxoTapKey)
		} else {
			script, err = common.P2TRScript(vtxoTapKey)
		}

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
	ctx context.Context, id string, events []domain.Event,
) error {
	if len(events) <= 0 {
		return nil
	}
	return s.repoManager.Events().Save(ctx, domain.RoundTopic, id, events)
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

func (s *covenantlessService) getCurrentRound() *domain.Round {
	s.currentRoundLock.Lock()
	defer s.currentRoundLock.Unlock()
	return s.currentRound
}

func (s *covenantlessService) markAsRedeemed(ctx context.Context, vtxo domain.Vtxo) error {
	if err := s.repoManager.Vtxos().RedeemVtxos(ctx, []domain.VtxoKey{vtxo.VtxoKey}); err != nil {
		return err
	}

	log.Debugf("vtxo %s:%d redeemed", vtxo.Txid, vtxo.VOut)
	return nil
}

func (s *covenantlessService) verifyForfeitTxsSigs(txs []string) error {
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

func fancyTime(timestamp int64, unit ports.TimeUnit) (fancyTime string) {
	if unit == ports.UnixTime {
		fancyTime = time.Unix(timestamp, 0).Format("2006-01-02 15:04:05")
	} else {
		fancyTime = fmt.Sprintf("block %d", timestamp)
	}
	return
}

func batchTreeEvents(txTree tree.TxTree, batchIndex int32, roundId string) []domain.Event {
	events := make([]domain.Event, 0)

	for _, lvl := range txTree {
		for _, node := range lvl {
			events = append(events, BatchTree{
				RoundEvent: domain.RoundEvent{
					Id:   roundId,
					Type: domain.EventTypeUndefined,
				},
				BatchIndex: batchIndex,
				Node:       node,
			})
		}
	}

	return events
}

func batchTreeSignatureEvents(txTree tree.TxTree, batchIndex int32, roundId string) []domain.Event {
	events := make([]domain.Event, 0)

	for level, lvl := range txTree {
		for levelIndex, node := range lvl {
			ptx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
			if err != nil {
				log.WithError(err).Warn("failed to parse tx")
				continue
			}

			sig := ptx.Inputs[0].TaprootKeySpendSig

			events = append(events, BatchTreeSignature{
				RoundEvent: domain.RoundEvent{
					Id:   roundId,
					Type: domain.EventTypeUndefined,
				},
				Topic:      []string{},
				BatchIndex: batchIndex,
				Level:      int32(level),
				LevelIndex: int32(levelIndex),
				Signature:  hex.EncodeToString(sig),
			})
		}
	}
	return events
}
