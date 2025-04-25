package application

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/note"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	log "github.com/sirupsen/logrus"
)

const (
	selectGapMinutes = float64(1)
	deleteGapMinutes = float64(5)
)

type timedTxRequest struct {
	domain.TxRequest
	boardingInputs []ports.BoardingInput
	notes          []note.Note
	timestamp      time.Time
	pingTimestamp  time.Time
	musig2Data     *tree.Musig2
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

func (m *txRequestsQueue) pushWithNotes(request domain.TxRequest, notes []note.Note) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.requests[request.Id]; ok {
		return fmt.Errorf("duplicated tx request %s", request.Id)
	}

	for _, note := range notes {
		for _, txRequest := range m.requests {
			for _, rNote := range txRequest.notes {
				if note.ID == rNote.ID {
					return fmt.Errorf("duplicated note %s", note)
				}
			}
		}
	}

	m.requests[request.Id] = &timedTxRequest{request, make([]ports.BoardingInput, 0), notes, time.Now(), time.Time{}, nil}
	return nil
}

func (m *txRequestsQueue) push(
	request domain.TxRequest,
	boardingInputs []ports.BoardingInput,
) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.requests[request.Id]; ok {
		return fmt.Errorf("duplicated tx request %s", request.Id)
	}

	for _, input := range request.Inputs {
		for _, pay := range m.requests {
			for _, pInput := range pay.Inputs {
				if input.VtxoKey.Txid == pInput.VtxoKey.Txid && input.VtxoKey.VOut == pInput.VtxoKey.VOut {
					return fmt.Errorf("duplicated input, %s:%d already used by tx request %s", input.VtxoKey.Txid, input.VtxoKey.VOut, pay.Id)
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
	m.requests[request.Id] = &timedTxRequest{request, boardingInputs, make([]note.Note, 0), now, now, nil}
	return nil
}

func (m *txRequestsQueue) pop(num int64) ([]domain.TxRequest, []ports.BoardingInput, []note.Note, []*tree.Musig2) {
	m.lock.Lock()
	defer m.lock.Unlock()

	requestsByTime := make([]timedTxRequest, 0, len(m.requests))
	for _, p := range m.requests {
		// Skip tx requests without registered receivers.
		if len(p.Receivers) <= 0 {
			continue
		}

		sinceLastPing := time.Since(p.pingTimestamp).Minutes()

		// Skip tx requests for which users didn't notify to be online in the last minute.
		if sinceLastPing > selectGapMinutes {
			// Cleanup the request from the map if greater than deleteGapMinutes
			// TODO move to dedicated function
			if sinceLastPing > deleteGapMinutes {
				log.Debugf("delete tx request %s : we didn't receive a ping in the last %d minutes", p.Id, int(deleteGapMinutes))
				delete(m.requests, p.Id)
			}

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

	requests := make([]domain.TxRequest, 0, num)
	boardingInputs := make([]ports.BoardingInput, 0)
	notes := make([]note.Note, 0)
	musig2Data := make([]*tree.Musig2, 0)
	for _, p := range requestsByTime[:num] {
		boardingInputs = append(boardingInputs, p.boardingInputs...)
		requests = append(requests, p.TxRequest)
		musig2Data = append(musig2Data, p.musig2Data)
		notes = append(notes, p.notes...)
		delete(m.requests, p.Id)
	}
	return requests, boardingInputs, notes, musig2Data
}

func (m *txRequestsQueue) update(request domain.TxRequest, musig2Data *tree.Musig2) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	r, ok := m.requests[request.Id]
	if !ok {
		return errTxRequestNotFound{request.Id}
	}

	// sum inputs = vtxos + boarding utxos + notes
	sumOfInputs := uint64(0)
	for _, input := range request.Inputs {
		sumOfInputs += input.Amount
	}

	for _, boardingInput := range r.boardingInputs {
		sumOfInputs += boardingInput.Amount
	}

	for _, note := range r.notes {
		sumOfInputs += uint64(note.Value)
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

func (m *txRequestsQueue) updatePingTimestamp(id string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	request, ok := m.requests[id]
	if !ok {
		return errTxRequestNotFound{id}
	}

	request.pingTimestamp = time.Now()
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
		vtxosToSign = append(vtxosToSign, request.Inputs...)
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

	if len(m.vtxos) == 0 || len(m.connectors) == 0 {
		return fmt.Errorf("forfeit txs map not initialized")
	}

	// verify the txs are valid
	validTxs, err := m.builder.VerifyForfeitTxs(m.vtxos, m.connectors, txs, m.connectorsIndex)
	if err != nil {
		return err
	}

	m.lock.Lock()
	defer m.lock.Unlock()

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

func validateProofs(ctx context.Context, vtxoRepo domain.VtxoRepository, proofs []SignedVtxoOutpoint) error {
	for _, signedVtxo := range proofs {
		vtxos, err := vtxoRepo.GetVtxos(ctx, []domain.VtxoKey{signedVtxo.Outpoint})
		if err != nil {
			return fmt.Errorf("vtxo not found: %s (%s)", signedVtxo.Outpoint, err)
		}

		if len(vtxos) < 1 {
			return fmt.Errorf("vtxo not found: %s", signedVtxo.Outpoint)
		}

		vtxo := vtxos[0]

		if err := signedVtxo.Proof.validate(vtxo); err != nil {
			return fmt.Errorf("invalid proof for vtxo %s (%s)", signedVtxo.Outpoint, err)
		}
	}

	return nil
}

// nip19toNostrProfile decodes a NIP-19 string and returns a nostr profile
// if nprofile => returns nostrRecipient
// if npub => craft nprofile from npub and defaultRelays
func nip19toNostrProfile(nostrRecipient string, defaultRelays []string) (string, error) {
	prefix, result, err := nip19.Decode(nostrRecipient)
	if err != nil {
		return "", fmt.Errorf("failed to decode NIP-19 string: %s", err)
	}

	var nprofileRecipient string

	switch prefix {
	case "nprofile":
		recipient, ok := result.(nostr.ProfilePointer)
		if !ok {
			return "", fmt.Errorf("invalid NIP-19 result: %v", result)
		}

		// validate public key
		if !nostr.IsValidPublicKey(recipient.PublicKey) {
			return "", fmt.Errorf("invalid nostr public key: %s", recipient.PublicKey)
		}

		// validate relays
		if len(recipient.Relays) == 0 {
			return "", fmt.Errorf("invalid nostr profile: at least one relay is required")
		}

		for _, relay := range recipient.Relays {
			if !nostr.IsValidRelayURL(relay) {
				return "", fmt.Errorf("invalid relay URL: %s", relay)
			}
		}

		nprofileRecipient = nostrRecipient
	case "npub":
		recipientPubkey, ok := result.(string)
		if !ok {
			return "", fmt.Errorf("invalid NIP-19 result: %v", result)
		}

		nprofileRecipient, err = nip19.EncodeProfile(recipientPubkey, defaultRelays)
		if err != nil {
			return "", fmt.Errorf("failed to encode nostr profile: %s", err)
		}
	default:
		return "", fmt.Errorf("invalid NIP-19 prefix: %s", prefix)
	}

	if nprofileRecipient == "" {
		return "", fmt.Errorf("invalid nostr recipient")
	}

	return nprofileRecipient, nil
}
