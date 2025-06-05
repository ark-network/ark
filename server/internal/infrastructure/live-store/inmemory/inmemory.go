package inmemory

import (
	"crypto/sha256"
	"fmt"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	selectGapMinutes = float64(1)
	deleteGapMinutes = float64(5)
)

func NewLiveStore(txBuilder ports.TxBuilder) ports.LiveStore {
	return &inMemoryLiveStore{
		txRequestsStore:           NewTxRequestsStore(),
		forfeitTxsStore:           NewForfeitTxsStore(txBuilder),
		offChainTxStore:           NewOffChainTxStore(),
		currentRoundStore:         NewCurrentRoundStore(),
		confirmationSessionsStore: NewConfirmationSessionsStore(),
		treeSigningSessions:       NewTreeSigningSessionsStore(),
		boardingInputsStore:       NewBoardingInputsStore(),
	}
}

func (s *inMemoryLiveStore) TxRequests() ports.TxRequestsStore { return s.txRequestsStore }
func (s *inMemoryLiveStore) ForfeitTxs() ports.ForfeitTxsStore { return s.forfeitTxsStore }
func (s *inMemoryLiveStore) OffchainTxs() ports.OffChainTxStore {
	return s.offChainTxStore
}
func (s *inMemoryLiveStore) CurrentRound() ports.CurrentRoundStore { return s.currentRoundStore }
func (s *inMemoryLiveStore) ConfirmationSessions() ports.ConfirmationSessionsStore {
	return s.confirmationSessionsStore
}
func (s *inMemoryLiveStore) TreeSigingSessions() ports.TreeSigningSessionsStore {
	return s.treeSigningSessions
}
func (s *inMemoryLiveStore) BoardingInputs() ports.BoardingInputsStore { return s.boardingInputsStore }

type inMemoryLiveStore struct {
	txRequestsStore           ports.TxRequestsStore
	forfeitTxsStore           ports.ForfeitTxsStore
	offChainTxStore           ports.OffChainTxStore
	currentRoundStore         ports.CurrentRoundStore
	confirmationSessionsStore ports.ConfirmationSessionsStore
	treeSigningSessions       ports.TreeSigningSessionsStore
	boardingInputsStore       ports.BoardingInputsStore
}

type txRequestStore struct {
	lock          sync.RWMutex
	requests      map[string]*ports.TimedTxRequest
	vtxos         map[string]struct{}
	vtxosToRemove []string
}

func NewTxRequestsStore() ports.TxRequestsStore {
	requestsById := make(map[string]*ports.TimedTxRequest)
	vtxos := make(map[string]struct{})
	vtxosToRemove := make([]string, 0)
	return &txRequestStore{
		requests:      requestsById,
		vtxos:         vtxos,
		vtxosToRemove: vtxosToRemove,
	}
}

func (m *txRequestStore) Len() int64 {
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

func (m *txRequestStore) Push(request domain.TxRequest, boardingInputs []ports.BoardingInput, musig2Data *tree.Musig2) error {
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
			for _, pBoardingInput := range request.BoardingInputs {
				if input.Txid == pBoardingInput.Txid && input.VOut == pBoardingInput.VOut {
					return fmt.Errorf("duplicated boarding input, %s:%d already used by tx request %s", input.Txid, input.VOut, request.Id)
				}
			}
		}
	}

	now := time.Now()
	m.requests[request.Id] = &ports.TimedTxRequest{
		TxRequest:      request,
		BoardingInputs: boardingInputs,
		Timestamp:      now,
		Musig2Data:     musig2Data,
	}
	for _, vtxo := range request.Inputs {
		if vtxo.IsNote() {
			continue
		}
		m.vtxos[vtxo.String()] = struct{}{}
	}
	return nil
}

func (m *txRequestStore) Pop(num int64) []ports.TimedTxRequest {
	m.lock.Lock()
	defer m.lock.Unlock()

	requestsByTime := make([]ports.TimedTxRequest, 0, len(m.requests))
	for _, p := range m.requests {
		// Skip tx requests without registered receivers.
		if len(p.Receivers) <= 0 {
			continue
		}

		requestsByTime = append(requestsByTime, *p)
	}
	sort.SliceStable(requestsByTime, func(i, j int) bool {
		return requestsByTime[i].Timestamp.Before(requestsByTime[j].Timestamp)
	})

	if num < 0 || num > int64(len(requestsByTime)) {
		num = int64(len(requestsByTime))
	}

	result := make([]ports.TimedTxRequest, 0, num)

	for _, p := range requestsByTime[:num] {
		result = append(result, p)
		for _, vtxo := range m.requests[p.Id].Inputs {
			m.vtxosToRemove = append(m.vtxosToRemove, vtxo.String())
		}
		delete(m.requests, p.Id)
	}

	return result
}

func (m *txRequestStore) Update(request domain.TxRequest, musig2Data *tree.Musig2) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	r, ok := m.requests[request.Id]
	if !ok {
		return fmt.Errorf("tx request %s not found", request.Id)
	}

	// sum inputs = vtxos + boarding utxos + notes + recovered vtxos
	sumOfInputs := uint64(0)
	for _, input := range request.Inputs {
		sumOfInputs += input.Amount
	}

	for _, boardingInput := range r.BoardingInputs {
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
		r.Musig2Data = musig2Data
	}
	return nil
}

func (m *txRequestStore) Delete(ids []string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, id := range ids {
		req, ok := m.requests[id]
		if !ok {
			continue
		}
		for _, vtxo := range req.Inputs {
			delete(m.vtxos, vtxo.String())
		}
		delete(m.requests, id)
	}
	return nil
}

func (m *txRequestStore) DeleteAll() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.requests = make(map[string]*ports.TimedTxRequest)
	m.vtxos = make(map[string]struct{})
	return nil
}

func (m *txRequestStore) DeleteVtxos() {
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, vtxo := range m.vtxosToRemove {
		delete(m.vtxos, vtxo)
	}
	m.vtxosToRemove = make([]string, 0)
}

func (m *txRequestStore) ViewAll(ids []string) ([]ports.TimedTxRequest, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	requests := make([]ports.TimedTxRequest, 0, len(m.requests))
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

func (m *txRequestStore) View(id string) (*domain.TxRequest, bool) {
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

func (m *txRequestStore) IncludesAny(outpoints []domain.VtxoKey) (bool, string) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	for _, out := range outpoints {
		if _, exists := m.vtxos[out.String()]; exists {
			return true, out.String()
		}
	}

	return false, ""
}

type forfeitTxsStore struct {
	lock            sync.RWMutex
	builder         ports.TxBuilder
	forfeitTxs      map[domain.VtxoKey]string
	connectors      tree.TxTree
	connectorsIndex map[string]domain.Outpoint
	vtxos           []domain.Vtxo
}

func NewForfeitTxsStore(txBuilder ports.TxBuilder) ports.ForfeitTxsStore {
	return &forfeitTxsStore{
		builder:    txBuilder,
		forfeitTxs: make(map[domain.VtxoKey]string),
	}
}

func (m *forfeitTxsStore) Init(connectors tree.TxTree, requests []domain.TxRequest) error {
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

func (m *forfeitTxsStore) Sign(txs []string) error {
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
func (m *forfeitTxsStore) Reset() {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.forfeitTxs = make(map[domain.VtxoKey]string)
	m.connectors = nil
	m.connectorsIndex = nil
	m.vtxos = nil
}
func (m *forfeitTxsStore) Pop() ([]string, error) {
	m.lock.Lock()
	defer func() {
		m.lock.Unlock()
		m.Reset()
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
func (m *forfeitTxsStore) AllSigned() bool {
	for _, txs := range m.forfeitTxs {
		if len(txs) == 0 {
			return false
		}
	}

	return true
}

func (s *forfeitTxsStore) Len() int {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return len(s.forfeitTxs)
}

func (s *forfeitTxsStore) GetConnectorsIndexes() map[string]domain.Outpoint {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.connectorsIndex
}

type offChainTxStore struct {
	lock        sync.RWMutex
	offchainTxs map[string]domain.OffchainTx
	inputs      map[string]struct{}
}

func NewOffChainTxStore() ports.OffChainTxStore {
	return &offChainTxStore{
		offchainTxs: make(map[string]domain.OffchainTx),
		inputs:      make(map[string]struct{}),
	}
}

func (m *offChainTxStore) Add(offchainTx domain.OffchainTx) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.offchainTxs[offchainTx.VirtualTxid] = offchainTx
	for _, tx := range offchainTx.CheckpointTxs {
		ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		for _, in := range ptx.UnsignedTx.TxIn {
			m.inputs[in.PreviousOutPoint.String()] = struct{}{}
		}
	}
}

func (m *offChainTxStore) Remove(virtualTxid string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	offchainTx, ok := m.offchainTxs[virtualTxid]
	if !ok {
		return
	}

	for _, tx := range offchainTx.CheckpointTxs {
		ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		for _, in := range ptx.UnsignedTx.TxIn {
			delete(m.inputs, in.PreviousOutPoint.String())
		}
	}
	delete(m.offchainTxs, virtualTxid)
}

func (m *offChainTxStore) Get(virtualTxid string) (domain.OffchainTx, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	offchainTx, ok := m.offchainTxs[virtualTxid]
	return offchainTx, ok
}

func (m *offChainTxStore) Includes(outpoint domain.VtxoKey) bool {
	m.lock.RLock()
	defer m.lock.RUnlock()
	_, exists := m.inputs[outpoint.String()]
	return exists
}

type currentRoundStore struct {
	lock  sync.RWMutex
	round *domain.Round
}

func NewCurrentRoundStore() ports.CurrentRoundStore {
	return &currentRoundStore{}
}
func (s *currentRoundStore) Upsert(fn func(m *domain.Round) *domain.Round) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.round = fn(s.round)
}
func (s *currentRoundStore) Get() *domain.Round {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.round
}

type confirmationSessionsStore struct {
	lock                sync.RWMutex
	intentsHashes       map[[32]byte]bool // hash --> confirmed
	numIntents          int
	numConfirmedIntents int
	confirmedC          chan struct{}
}

func NewConfirmationSessionsStore() ports.ConfirmationSessionsStore {
	return &confirmationSessionsStore{
		confirmedC: make(chan struct{}),
	}
}

func (c *confirmationSessionsStore) Init(intentIDsHashes [][32]byte) {
	c.lock.Lock()
	defer c.lock.Unlock()

	hashes := make(map[[32]byte]bool)
	for _, hash := range intentIDsHashes {
		hashes[hash] = false
	}

	c.intentsHashes = hashes
	c.numIntents = len(intentIDsHashes)
}

func (s *confirmationSessionsStore) Confirm(intentId string) error {
	hash := sha256.Sum256([]byte(intentId))
	s.lock.Lock()
	defer s.lock.Unlock()
	alreadyConfirmed, ok := s.intentsHashes[hash]
	if !ok {
		return fmt.Errorf("intent hash not found")
	}

	if alreadyConfirmed {
		return nil
	}

	s.numConfirmedIntents++
	s.intentsHashes[hash] = true

	if s.numConfirmedIntents == s.numIntents {
		select {
		case s.confirmedC <- struct{}{}:
		default:
		}
	}

	return nil
}

func (c *confirmationSessionsStore) Get() *ports.ConfirmationSessions {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return &ports.ConfirmationSessions{
		IntentsHashes:       c.intentsHashes,
		NumIntents:          c.numIntents,
		NumConfirmedIntents: c.numConfirmedIntents,
		ConfirmedC:          c.confirmedC,
	}
}

func (c *confirmationSessionsStore) Reset() {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.intentsHashes = make(map[[32]byte]bool)
	c.numIntents = 0
	c.numConfirmedIntents = 0
}

type treeSigningSessionsStore struct {
	lock     sync.RWMutex
	sessions map[string]*ports.MusigSigningSession
}

func NewTreeSigningSessionsStore() ports.TreeSigningSessionsStore {
	return &treeSigningSessionsStore{sessions: make(map[string]*ports.MusigSigningSession)}
}
func (s *treeSigningSessionsStore) New(
	roundId string, uniqueSignersPubKeys map[string]struct{},
) *ports.MusigSigningSession {
	s.lock.Lock()
	defer s.lock.Unlock()
	sess := &ports.MusigSigningSession{
		Cosigners:   uniqueSignersPubKeys,
		NbCosigners: len(uniqueSignersPubKeys) + 1, // server included
		Nonces:      make(map[secp256k1.PublicKey]tree.TreeNonces),
		NonceDoneC:  make(chan struct{}),
		Signatures:  make(map[secp256k1.PublicKey]tree.TreePartialSigs),
		SigDoneC:    make(chan struct{}),
	}
	s.sessions[roundId] = sess
	return sess
}
func (s *treeSigningSessionsStore) Get(roundId string) (*ports.MusigSigningSession, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	sess, ok := s.sessions[roundId]
	return sess, ok
}
func (s *treeSigningSessionsStore) Delete(roundId string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.sessions, roundId)
}

func NewBoardingInputsStore() ports.BoardingInputsStore {
	return &boardingInputsStore{}
}

type boardingInputsStore struct {
	lock        sync.RWMutex
	numOfInputs int
}

func (b *boardingInputsStore) Set(numOfInputs int) {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.numOfInputs = numOfInputs
}

func (b *boardingInputsStore) Get() int {
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.numOfInputs
}
