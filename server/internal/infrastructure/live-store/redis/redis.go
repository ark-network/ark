package redis

import (
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
)

func NewLiveStore() ports.LiveStore {
	return &redisLiveStore{
		txRequestStore:        NewTxRequestStore(),
		forfeitTxsStore:       NewForfeitTxsStore(),
		offChainTxInputsStore: NewOutpointStore(),
		roundInputsStore:      NewOutpointStore(),
		currentRoundStore:     NewCurrentRoundStore(),
		treeSigningSessions:   NewTreeSigningSessionsStore(),
	}
}

func (s *redisLiveStore) TxRequest() ports.TxRequestStore   { return s.txRequestStore }
func (s *redisLiveStore) ForfeitTxs() ports.ForfeitTxsStore { return s.forfeitTxsStore }
func (s *redisLiveStore) OffChainTxInputs() ports.OutpointStore {
	return s.offChainTxInputsStore
}
func (s *redisLiveStore) RoundInputs() ports.OutpointStore      { return s.roundInputsStore }
func (s *redisLiveStore) CurrentRound() ports.CurrentRoundStore { return s.currentRoundStore }
func (s *redisLiveStore) TreeSigingSessions() ports.TreeSigningSessionsStore {
	return s.treeSigningSessions
}

type redisLiveStore struct {
	txRequestStore        ports.TxRequestStore
	forfeitTxsStore       ports.ForfeitTxsStore
	offChainTxInputsStore ports.OutpointStore
	roundInputsStore      ports.OutpointStore
	currentRoundStore     ports.CurrentRoundStore
	treeSigningSessions   ports.TreeSigningSessionsStore
}

type txRequestStore struct{}

func NewTxRequestStore() ports.TxRequestStore { return &txRequestStore{} }

func (s *txRequestStore) Len() int64 { panic("not implemented") }
func (s *txRequestStore) Push(request domain.TxRequest, boardingInputs []ports.BoardingInput, musig2Data *tree.Musig2) error {
	panic("not implemented")
}
func (s *txRequestStore) Pop(num int64) ([]domain.TxRequest, []ports.BoardingInput, []*tree.Musig2) {
	panic("not implemented")
}
func (s *txRequestStore) Update(request domain.TxRequest, musig2Data *tree.Musig2) error {
	panic("not implemented")
}
func (s *txRequestStore) UpdatePingTimestamp(id string) error { panic("not implemented") }
func (s *txRequestStore) Delete(ids []string) error           { panic("not implemented") }
func (s *txRequestStore) DeleteAll() error                    { panic("not implemented") }
func (s *txRequestStore) ViewAll(ids []string) ([]ports.TimedTxRequest, error) {
	panic("not implemented")
}
func (s *txRequestStore) View(id string) (*domain.TxRequest, bool) { panic("not implemented") }

type forfeitTxsStore struct{}

func NewForfeitTxsStore() ports.ForfeitTxsStore { return &forfeitTxsStore{} }

func (s *forfeitTxsStore) Init(connectors tree.TxTree, requests []domain.TxRequest) error {
	panic("not implemented")
}
func (s *forfeitTxsStore) Sign(txs []string) error { panic("not implemented") }
func (s *forfeitTxsStore) Reset()                  { panic("not implemented") }
func (s *forfeitTxsStore) Pop() ([]string, error)  { panic("not implemented") }
func (s *forfeitTxsStore) AllSigned() bool         { panic("not implemented") }
func (s *forfeitTxsStore) Len() int                { panic("not implemented") }
func (s *forfeitTxsStore) GetConnectorsIndexes() map[string]domain.Outpoint {
	panic("not implemented")
}

type outpointStore struct{}

func NewOutpointStore() ports.OutpointStore { return &outpointStore{} }

func (s *outpointStore) Add(outpoints []domain.VtxoKey)        { panic("not implemented") }
func (s *outpointStore) Remove(outpoints []domain.VtxoKey)     { panic("not implemented") }
func (s *outpointStore) Includes(outpoint domain.VtxoKey) bool { panic("not implemented") }
func (s *outpointStore) IncludesAny(outpoints []domain.VtxoKey) (bool, string) {
	panic("not implemented")
}

type currentRoundStore struct{}

func NewCurrentRoundStore() ports.CurrentRoundStore { return &currentRoundStore{} }

func (s *currentRoundStore) Upsert(round *domain.Round) { panic("not implemented") }
func (s *currentRoundStore) Get() *domain.Round         { panic("not implemented") }

type treeSigningSessionsStore struct{}

func NewTreeSigningSessionsStore() ports.TreeSigningSessionsStore {
	return &treeSigningSessionsStore{}
}

func (s *treeSigningSessionsStore) NewSession(roundId string, uniqueSignersPubKeys map[string]struct{}) *ports.MusigSigningSession {
	panic("not implemented")
}
func (s *treeSigningSessionsStore) GetSession(roundId string) (*ports.MusigSigningSession, bool) {
	panic("not implemented")
}
func (s *treeSigningSessionsStore) DeleteSession(roundId string) { panic("not implemented") }
