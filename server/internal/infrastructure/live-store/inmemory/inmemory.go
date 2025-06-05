package inmemory

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"sort"
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
		txRequestStore:        NewTxRequestStore(),
		forfeitTxsStore:       NewForfeitTxsStore(txBuilder),
		offChainTxInputsStore: NewOutpointStore(),
		roundInputsStore:      NewOutpointStore(),
		currentRoundStore:     NewCurrentRoundStore(),
		treeSigningSessions:   NewTreeSigningSessionsStore(),
		boardingInputsStore:   NewBoardingInputsStore(),
	}
}

func (s *inMemoryLiveStore) TxRequest() ports.TxRequestStore   { return s.txRequestStore }
func (s *inMemoryLiveStore) ForfeitTxs() ports.ForfeitTxsStore { return s.forfeitTxsStore }
func (s *inMemoryLiveStore) OffChainTxInputs() ports.OutpointStore {
	return s.offChainTxInputsStore
}
func (s *inMemoryLiveStore) RoundInputs() ports.OutpointStore      { return s.roundInputsStore }
func (s *inMemoryLiveStore) CurrentRound() ports.CurrentRoundStore { return s.currentRoundStore }
func (s *inMemoryLiveStore) TreeSigingSessions() ports.TreeSigningSessionsStore {
	return s.treeSigningSessions
}
func (s *inMemoryLiveStore) BoardingInputs() ports.BoardingInputsStore { return s.boardingInputsStore }

type inMemoryLiveStore struct {
	txRequestStore        ports.TxRequestStore
	forfeitTxsStore       ports.ForfeitTxsStore
	offChainTxInputsStore ports.OutpointStore
	roundInputsStore      ports.OutpointStore
	currentRoundStore     ports.CurrentRoundStore
	treeSigningSessions   ports.TreeSigningSessionsStore
	boardingInputsStore   ports.BoardingInputsStore
}

type txRequestStore struct {
	lock     sync.RWMutex
	requests map[string]*ports.TimedTxRequest
}

func NewTxRequestStore() ports.TxRequestStore {
	return &txRequestStore{requests: make(map[string]*ports.TimedTxRequest)}
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
		for _, v := range m.requests {
			for _, pBoardingInput := range v.BoardingInputs {
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
		PingTimestamp:  now,
		Musig2Data:     musig2Data,
	}
	return nil
}

func (m *txRequestStore) Pop(num int64) ([]domain.TxRequest, []ports.BoardingInput, []*tree.Musig2) {
	m.lock.Lock()
	defer m.lock.Unlock()

	requestsByTime := make([]*ports.TimedTxRequest, 0, len(m.requests))
	for _, p := range m.requests {
		// Skip tx requests without registered receivers.
		if len(p.Receivers) <= 0 {
			continue
		}

		sinceLastPing := time.Since(p.PingTimestamp).Minutes()
		// Skip tx requests for which users didn't notify to be online in the last minute.
		if sinceLastPing > selectGapMinutes {
			// Cleanup the request from the map if greater than deleteGapMinutes
			// TODO move to dedicated function
			if sinceLastPing > deleteGapMinutes {
				log.Debugf("delete tx request %s : we didn't receive a ping in the last %d minutes", p.Id, int(deleteGapMinutes))
				delete(m.requests, p.TxRequest.Id)
			}
			continue
		}
		requestsByTime = append(requestsByTime, p)
	}

	sort.SliceStable(requestsByTime, func(i, j int) bool {
		return requestsByTime[i].Timestamp.Before(requestsByTime[j].Timestamp)
	})

	if num < 0 || num > int64(len(requestsByTime)) {
		num = int64(len(requestsByTime))
	}

	requests := make([]domain.TxRequest, 0, num)
	boardingInputs := make([]ports.BoardingInput, 0)
	musig2Data := make([]*tree.Musig2, 0)
	for _, p := range requestsByTime[:num] {
		boardingInputs = append(boardingInputs, p.BoardingInputs...)
		requests = append(requests, p.TxRequest)
		musig2Data = append(musig2Data, p.Musig2Data)
		delete(m.requests, p.TxRequest.Id)
	}
	return requests, boardingInputs, musig2Data
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

func (m *txRequestStore) UpdatePingTimestamp(id string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	request, ok := m.requests[id]
	if !ok {
		return fmt.Errorf("tx request %s not found", id)
	}

	request.PingTimestamp = time.Now()
	return nil
}

func (m *txRequestStore) Delete(ids []string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, id := range ids {
		delete(m.requests, id)
	}
	return nil
}

func (m *txRequestStore) DeleteAll() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.requests = make(map[string]*ports.TimedTxRequest)
	return nil
}

func (m *txRequestStore) ViewAll(ids []string) ([]ports.TimedTxRequest, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	results := make([]ports.TimedTxRequest, 0, len(m.requests))
	for _, request := range m.requests {
		if len(ids) > 0 {
			for _, id := range ids {
				if request.Id == id {
					results = append(results, *request)
					break
				}
			}
			continue
		}

		results = append(results, *request)
	}
	return results, nil
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

func (s *forfeitTxsStore) Init(connectors tree.TxTree, requests []domain.TxRequest) error {
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

	s.lock.Lock()
	defer s.lock.Unlock()

	s.vtxos = vtxosToSign
	s.connectors = connectors

	// init the forfeit txs map
	for _, vtxo := range vtxosToSign {
		s.forfeitTxs[vtxo.VtxoKey] = ""
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

	s.connectorsIndex = connectorsIndex

	return nil
}

func (s *forfeitTxsStore) Sign(txs []string) error {
	if len(txs) == 0 {
		return nil
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	if len(s.vtxos) == 0 || len(s.connectors) == 0 {
		return fmt.Errorf("forfeit txs map not initialized")
	}

	// verify the txs are valid
	validTxs, err := s.builder.VerifyForfeitTxs(s.vtxos, s.connectors, txs, s.connectorsIndex)
	if err != nil {
		return err
	}

	for vtxoKey, txs := range validTxs {
		if _, ok := s.forfeitTxs[vtxoKey]; !ok {
			return fmt.Errorf("unexpected forfeit tx, vtxo %s is not in the batch", vtxoKey)
		}
		s.forfeitTxs[vtxoKey] = txs
	}

	return nil
}
func (s *forfeitTxsStore) Reset() {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.forfeitTxs = make(map[domain.VtxoKey]string)
	s.connectors = nil
	s.connectorsIndex = nil
	s.vtxos = nil
}
func (s *forfeitTxsStore) Pop() ([]string, error) {
	s.lock.Lock()
	defer func() {
		s.lock.Unlock()
		s.Reset()
	}()

	txs := make([]string, 0)
	for vtxo, forfeit := range s.forfeitTxs {
		if len(forfeit) == 0 {
			return nil, fmt.Errorf("missing forfeit tx for vtxo %s", vtxo)
		}
		txs = append(txs, forfeit)
	}

	return txs, nil
}
func (s *forfeitTxsStore) AllSigned() bool {
	for _, txs := range s.forfeitTxs {
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

type outpointStore struct {
	lock      sync.RWMutex
	outpoints map[string]struct{}
}

func NewOutpointStore() ports.OutpointStore {
	return &outpointStore{outpoints: make(map[string]struct{})}
}

func (s *outpointStore) Add(outpoints []domain.VtxoKey) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, o := range outpoints {
		s.outpoints[o.String()] = struct{}{}
	}
}
func (s *outpointStore) Remove(outpoints []domain.VtxoKey) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, o := range outpoints {
		delete(s.outpoints, o.String())
	}
}
func (s *outpointStore) Includes(outpoint domain.VtxoKey) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	_, ok := s.outpoints[outpoint.String()]
	return ok
}
func (s *outpointStore) IncludesAny(outpoints []domain.VtxoKey) (bool, string) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	for _, o := range outpoints {
		if _, ok := s.outpoints[o.String()]; ok {
			return true, o.String()
		}
	}
	return false, ""
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

type treeSigningSessionsStore struct {
	lock     sync.RWMutex
	sessions map[string]*ports.MusigSigningSession
}

func NewTreeSigningSessionsStore() ports.TreeSigningSessionsStore {
	return &treeSigningSessionsStore{sessions: make(map[string]*ports.MusigSigningSession)}
}
func (s *treeSigningSessionsStore) NewSession(
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
func (s *treeSigningSessionsStore) GetSession(roundId string) (*ports.MusigSigningSession, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	sess, ok := s.sessions[roundId]
	return sess, ok
}
func (s *treeSigningSessionsStore) DeleteSession(roundId string) {
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
