package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
)

type timedTxRequest struct {
	domain.TxRequest
	boardingInputs []ports.BoardingInput
	timestamp      time.Time
	musig2Data     *tree.Musig2
}

func (t timedTxRequest) hashID() [32]byte {
	return sha256.Sum256([]byte(t.Id))
}

type txRequestsQueue struct {
	lock     *sync.RWMutex
	requests map[string]*timedTxRequest
}

func newTxRequestsQueue() *txRequestsQueue {
	requestsById := make(map[string]*timedTxRequest)
	lock := &sync.RWMutex{}
	return &txRequestsQueue{lock, requestsById}
}

func (m *txRequestsQueue) len() int64 {
	m.lock.RLock()
	defer m.lock.RUnlock()

	count := int64(0)
	for _, p := range m.requests {
		if len(p.Receivers) > 0 {
			count++
		}
	}
	return count
}

func (m *txRequestsQueue) push(
	request domain.TxRequest,
	boardingInputs []ports.BoardingInput,
	musig2Data *tree.Musig2,
) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.requests[request.Id]; ok {
		return fmt.Errorf("duplicated tx request %s", request.Id)
	}

	for _, input := range request.Inputs {
		for _, pay := range m.requests {
			for _, pInput := range pay.Inputs {
				if input.Txid == pInput.Txid && input.VOut == pInput.VOut {
					return fmt.Errorf("duplicated input, %s:%d already used by tx request %s", input.Txid, input.VOut, pay.Id)
				}
			}
		}
	}

	for _, input := range boardingInputs {
		for _, request := range m.requests {
			for _, pBoardingInput := range request.boardingInputs {
				if input.Txid == pBoardingInput.Txid && input.VOut == pBoardingInput.VOut {
					return fmt.Errorf("duplicated boarding input, %s:%d already used by tx request %s", input.Txid, input.VOut, request.Id)
				}
			}
		}
	}

	now := time.Now()
	m.requests[request.Id] = &timedTxRequest{request, boardingInputs, now, musig2Data}
	return nil
}

func (m *txRequestsQueue) pop(num int64) []timedTxRequest {
	m.lock.Lock()
	defer m.lock.Unlock()

	requestsByTime := make([]timedTxRequest, 0, len(m.requests))
	for _, p := range m.requests {
		// Skip tx requests without registered receivers.
		if len(p.Receivers) <= 0 {
			continue
		}

		requestsByTime = append(requestsByTime, *p)
	}
	sort.SliceStable(requestsByTime, func(i, j int) bool {
		return requestsByTime[i].timestamp.Before(requestsByTime[j].timestamp)
	})

	if num < 0 || num > int64(len(requestsByTime)) {
		num = int64(len(requestsByTime))
	}

	result := make([]timedTxRequest, 0, num)

	for _, p := range requestsByTime[:num] {
		result = append(result, p)
		delete(m.requests, p.Id)
	}

	return result
}

func (m *txRequestsQueue) update(request domain.TxRequest, musig2Data *tree.Musig2) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	r, ok := m.requests[request.Id]
	if !ok {
		return errTxRequestNotFound{request.Id}
	}

	// sum inputs = vtxos + boarding utxos + notes + recovered vtxos
	sumOfInputs := uint64(0)
	for _, input := range request.Inputs {
		sumOfInputs += input.Amount
	}

	for _, boardingInput := range r.boardingInputs {
		sumOfInputs += boardingInput.Amount
	}

	// sum outputs = receivers VTXOs
	sumOfOutputs := uint64(0)
	for _, receiver := range request.Receivers {
		sumOfOutputs += receiver.Amount
	}

	if sumOfInputs != sumOfOutputs {
		return fmt.Errorf("sum of inputs %d does not match sum of outputs %d", sumOfInputs, sumOfOutputs)
	}

	r.TxRequest = request

	if musig2Data != nil {
		r.musig2Data = musig2Data
	}
	return nil
}

func (m *txRequestsQueue) delete(ids []string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, id := range ids {
		delete(m.requests, id)
	}
	return nil
}

func (m *txRequestsQueue) deleteAll() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.requests = make(map[string]*timedTxRequest)
	return nil
}

func (m *txRequestsQueue) viewAll(ids []string) ([]timedTxRequest, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	requests := make([]timedTxRequest, 0, len(m.requests))
	for _, request := range m.requests {
		if len(ids) > 0 {
			for _, id := range ids {
				if request.Id == id {
					requests = append(requests, *request)
					break
				}
			}
			continue
		}
		requests = append(requests, *request)
	}
	return requests, nil
}

func (m *txRequestsQueue) view(id string) (*domain.TxRequest, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	request, ok := m.requests[id]
	if !ok {
		return nil, false
	}

	return &domain.TxRequest{
		Id:        request.Id,
		Inputs:    request.Inputs,
		Receivers: request.Receivers,
	}, true
}

type forfeitTxsMap struct {
	lock    *sync.RWMutex
	builder ports.TxBuilder

	forfeitTxs      map[domain.VtxoKey]string
	connectors      tree.TxTree
	connectorsIndex map[string]domain.Outpoint
	vtxos           []domain.Vtxo
}

func newForfeitTxsMap(txBuilder ports.TxBuilder) *forfeitTxsMap {
	return &forfeitTxsMap{
		lock:            &sync.RWMutex{},
		builder:         txBuilder,
		forfeitTxs:      make(map[domain.VtxoKey]string),
		connectors:      nil,
		connectorsIndex: nil,
		vtxos:           nil,
	}
}

func (m *forfeitTxsMap) init(connectors tree.TxTree, requests []domain.TxRequest) error {
	vtxosToSign := make([]domain.Vtxo, 0)
	for _, request := range requests {
		for _, vtxo := range request.Inputs {
			// If the vtxo is swept or is a note, it doens't require to be forfeited so we skip it
			if !vtxo.RequiresForfeit() {
				continue
			}
			vtxosToSign = append(vtxosToSign, vtxo)
		}
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	m.vtxos = vtxosToSign
	m.connectors = connectors

	// init the forfeit txs map
	for _, vtxo := range vtxosToSign {
		m.forfeitTxs[vtxo.VtxoKey] = ""
	}

	// create the connectors index
	connectorsIndex := make(map[string]domain.Outpoint)

	if len(vtxosToSign) > 0 {
		connectorsOutpoints := make([]domain.Outpoint, 0)

		leaves := connectors.Leaves()
		if len(leaves) == 0 {
			return fmt.Errorf("no connectors found")
		}

		for _, n := range leaves {
			connectorsOutpoints = append(connectorsOutpoints, domain.Outpoint{
				Txid: n.Txid,
				VOut: 0,
			})
		}

		// sort lexicographically
		sort.Slice(vtxosToSign, func(i, j int) bool {
			return vtxosToSign[i].String() < vtxosToSign[j].String()
		})

		if len(vtxosToSign) > len(connectorsOutpoints) {
			return fmt.Errorf("more vtxos to sign than outpoints, %d > %d", len(vtxosToSign), len(connectorsOutpoints))
		}

		for i, vtxo := range vtxosToSign {
			connectorsIndex[vtxo.String()] = connectorsOutpoints[i]
		}
	}

	m.connectorsIndex = connectorsIndex

	return nil
}

func (m *forfeitTxsMap) sign(txs []string) error {
	if len(txs) == 0 {
		return nil
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	if len(m.vtxos) == 0 || len(m.connectors) == 0 {
		return fmt.Errorf("forfeit txs map not initialized")
	}

	// verify the txs are valid
	validTxs, err := m.builder.VerifyForfeitTxs(m.vtxos, m.connectors, txs, m.connectorsIndex)
	if err != nil {
		return err
	}

	for vtxoKey, txs := range validTxs {
		if _, ok := m.forfeitTxs[vtxoKey]; !ok {
			return fmt.Errorf("unexpected forfeit tx, vtxo %s is not in the batch", vtxoKey)
		}
		m.forfeitTxs[vtxoKey] = txs
	}

	return nil
}

func (m *forfeitTxsMap) reset() {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.forfeitTxs = make(map[domain.VtxoKey]string)
	m.connectors = nil
	m.connectorsIndex = nil
	m.vtxos = nil
}

func (m *forfeitTxsMap) pop() ([]string, error) {
	m.lock.Lock()
	defer func() {
		m.lock.Unlock()
		m.reset()
	}()

	txs := make([]string, 0)
	for vtxo, forfeit := range m.forfeitTxs {
		if len(forfeit) == 0 {
			return nil, fmt.Errorf("missing forfeit tx for vtxo %s", vtxo)
		}
		txs = append(txs, forfeit)
	}

	return txs, nil
}

func (m *forfeitTxsMap) allSigned() bool {
	for _, txs := range m.forfeitTxs {
		if len(txs) == 0 {
			return false
		}
	}

	return true
}

type outpointMap struct {
	lock      *sync.RWMutex
	outpoints map[string]struct{}
}

func newOutpointMap() *outpointMap {
	return &outpointMap{
		lock:      &sync.RWMutex{},
		outpoints: make(map[string]struct{}),
	}
}

func (r *outpointMap) add(outpoints []domain.VtxoKey) {
	r.lock.Lock()
	defer r.lock.Unlock()
	for _, out := range outpoints {
		r.outpoints[out.String()] = struct{}{}
	}
}

func (r *outpointMap) removeRoundInputs(round domain.Round) {
	vtxoKeys := make([]domain.VtxoKey, 0)
	for _, req := range round.TxRequests {
		for _, in := range req.Inputs {
			vtxoKeys = append(vtxoKeys, in.VtxoKey)
		}
	}
	r.remove(vtxoKeys)
}

func (r *outpointMap) remove(outpoints []domain.VtxoKey) {
	r.lock.Lock()
	defer r.lock.Unlock()
	for _, out := range outpoints {
		delete(r.outpoints, out.String())
	}
}

func (r *outpointMap) includes(outpoint domain.VtxoKey) bool {
	r.lock.RLock()
	defer r.lock.RUnlock()
	_, exists := r.outpoints[outpoint.String()]
	return exists
}

func (r *outpointMap) includesAny(outpoints []domain.VtxoKey) (bool, string) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	for _, out := range outpoints {
		if _, exists := r.outpoints[out.String()]; exists {
			return true, out.String()
		}
	}

	return false, ""
}

type offchainTxsMap struct {
	lock        *sync.RWMutex
	offchainTxs map[string]domain.OffchainTx
}

func newOffchainTxsMap() *offchainTxsMap {
	return &offchainTxsMap{
		lock:        &sync.RWMutex{},
		offchainTxs: make(map[string]domain.OffchainTx),
	}
}

func (m *offchainTxsMap) add(offchainTx domain.OffchainTx) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.offchainTxs[offchainTx.VirtualTxid] = offchainTx
}

func (m *offchainTxsMap) remove(virtualTxid string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.offchainTxs, virtualTxid)
}

func (m *offchainTxsMap) get(offchainTxid string) (domain.OffchainTx, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	offchainTx, ok := m.offchainTxs[offchainTxid]
	return offchainTx, ok
}

// onchainOutputs iterates over all the nodes' outputs in the vtxo tree and checks their onchain state
// returns the sweepable outputs as ports.SweepInput mapped by their expiration time
func findSweepableOutputs(
	ctx context.Context,
	walletSvc ports.WalletService,
	txbuilder ports.TxBuilder,
	schedulerUnit ports.TimeUnit,
	vtxoTree tree.TxTree,
) (map[int64][]ports.SweepInput, error) {
	sweepableOutputs := make(map[int64][]ports.SweepInput)
	blocktimeCache := make(map[string]int64) // txid -> blocktime / blockheight
	nodesToCheck := vtxoTree[0]              // init with the root

	for len(nodesToCheck) > 0 {
		newNodesToCheck := make([]tree.Node, 0)

		for _, node := range nodesToCheck {
			isConfirmed, height, blocktime, err := walletSvc.IsTransactionConfirmed(ctx, node.Txid)
			if err != nil {
				return nil, err
			}

			var expirationTime int64
			var sweepInput ports.SweepInput

			if !isConfirmed {
				if _, ok := blocktimeCache[node.ParentTxid]; !ok {
					isConfirmed, height, blocktime, err := walletSvc.IsTransactionConfirmed(ctx, node.ParentTxid)
					if !isConfirmed || err != nil {
						return nil, fmt.Errorf("tx %s not found", node.ParentTxid)
					}

					if schedulerUnit == ports.BlockHeight {
						blocktimeCache[node.ParentTxid] = height
					} else {
						blocktimeCache[node.ParentTxid] = blocktime
					}
				}

				var vtxoTreeExpiry *common.RelativeLocktime
				vtxoTreeExpiry, sweepInput, err = txbuilder.GetSweepInput(node)
				if err != nil {
					return nil, err
				}
				expirationTime = blocktimeCache[node.ParentTxid] + int64(vtxoTreeExpiry.Value)
			} else {
				// cache the blocktime for future use
				if schedulerUnit == ports.BlockHeight {
					blocktimeCache[node.Txid] = height
				} else {
					blocktimeCache[node.Txid] = blocktime
				}

				// if the tx is onchain, it means that the input is spent
				// add the children to the nodes in order to check them during the next iteration
				// We will return the error below, but are we going to schedule the tasks for the "children roots"?
				if !node.Leaf {
					children := vtxoTree.Children(node.Txid)
					newNodesToCheck = append(newNodesToCheck, children...)
				}
				continue
			}

			if _, ok := sweepableOutputs[expirationTime]; !ok {
				sweepableOutputs[expirationTime] = make([]ports.SweepInput, 0)
			}
			sweepableOutputs[expirationTime] = append(sweepableOutputs[expirationTime], sweepInput)
		}

		nodesToCheck = newNodesToCheck
	}

	return sweepableOutputs, nil
}

func getSpentVtxos(requests map[string]domain.TxRequest) []domain.VtxoKey {
	vtxos := make([]domain.VtxoKey, 0)
	for _, request := range requests {
		for _, vtxo := range request.Inputs {
			vtxos = append(vtxos, vtxo.VtxoKey)
		}
	}
	return vtxos
}

func decodeTx(offchainTx domain.OffchainTx) (string, []domain.VtxoKey, []domain.Vtxo, error) {
	ins := make([]domain.VtxoKey, 0, len(offchainTx.CheckpointTxs))
	for _, checkpointTx := range offchainTx.CheckpointTxs {
		checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(checkpointTx), true)
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to parse checkpoint tx: %s", err)
		}
		ins = append(ins, domain.VtxoKey{
			Txid: checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String(),
			VOut: checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Index,
		})
	}

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(offchainTx.VirtualTx), true)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to parse partial tx: %s", err)
	}
	txid := ptx.UnsignedTx.TxHash().String()

	outs := make([]domain.Vtxo, 0, len(ptx.UnsignedTx.TxOut))
	for outIndex, out := range ptx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, tree.ANCHOR_PKSCRIPT) {
			continue
		}
		outs = append(outs, domain.Vtxo{
			VtxoKey: domain.VtxoKey{
				Txid: txid,
				VOut: uint32(outIndex),
			},
			PubKey:         hex.EncodeToString(out.PkScript[2:]),
			Amount:         uint64(out.Value),
			ExpireAt:       offchainTx.ExpiryTimestamp,
			CommitmentTxid: offchainTx.RootCommitmentTxId,
			RedeemTx:       offchainTx.VirtualTx,
			CreatedAt:      offchainTx.EndingTimestamp,
		})
	}

	return txid, ins, outs, nil
}

func findFirstRoundToExpire(vtxos []domain.Vtxo) (expiration int64, roundTxid string) {
	for i, vtxo := range vtxos {
		if i == 0 || vtxo.ExpireAt < expiration {
			roundTxid = vtxo.CommitmentTxid
			expiration = vtxo.ExpireAt
		}
	}

	return
}

func newBoardingInput(
	tx wire.MsgTx,
	input ports.Input,
	serverPubKey *secp256k1.PublicKey,
	boardingExitDelay common.RelativeLocktime,
) (*ports.BoardingInput, error) {
	if len(tx.TxOut) <= int(input.VOut) {
		return nil, fmt.Errorf("output not found")
	}

	output := tx.TxOut[input.VOut]

	boardingScript, err := tree.ParseVtxoScript(input.Tapscripts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse boarding utxo taproot tree: %s", err)
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
		return nil, fmt.Errorf(
			"invalid boarding utxo taproot key: got %x expected %x",
			output.PkScript, expectedScriptPubkey,
		)
	}

	if err := boardingScript.Validate(serverPubKey, boardingExitDelay); err != nil {
		return nil, err
	}

	return &ports.BoardingInput{
		Amount: uint64(output.Value),
		Input:  input,
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

func getNewVtxosFromRound(round *domain.Round) []domain.Vtxo {
	if len(round.VtxoTree) <= 0 {
		return nil
	}

	now := time.Now()
	createdAt := now.Unix()
	expireAt := round.ExpiryTimestamp()

	leaves := round.VtxoTree.Leaves()
	vtxos := make([]domain.Vtxo, 0)
	for _, node := range leaves {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
		if err != nil {
			log.WithError(err).Warn("failed to parse tx")
			continue
		}
		for i, out := range tx.UnsignedTx.TxOut {
			if bytes.Equal(out.PkScript, tree.ANCHOR_PKSCRIPT) {
				continue
			}

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
				ExpireAt:  expireAt,
			})
		}
	}
	return vtxos
}
