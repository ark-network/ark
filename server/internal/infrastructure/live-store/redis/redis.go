package redis

import (
	"context"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
)

func NewLiveStore() ports.LiveStore {
	return &redisLiveStore{
		txRequestsStore:           NewTxRequestsStore(),
		forfeitTxsStore:           NewForfeitTxsStore(),
		offChainTxStore:           NewOffChainTxStore(),
		currentRoundStore:         NewCurrentRoundStore(),
		confirmationSessionsStore: NewConfirmationSessionsStore(),
		treeSigningSessions:       NewTreeSigningSessionsStore(),
		boardingInputsStore:       NewBoardingInputsStore(),
	}
}

func (s *redisLiveStore) TxRequests() ports.TxRequestsStore     { return s.txRequestsStore }
func (s *redisLiveStore) ForfeitTxs() ports.ForfeitTxsStore     { return s.forfeitTxsStore }
func (s *redisLiveStore) OffchainTxs() ports.OffChainTxStore    { return s.offChainTxStore }
func (s *redisLiveStore) CurrentRound() ports.CurrentRoundStore { return s.currentRoundStore }
func (s *redisLiveStore) ConfirmationSessions() ports.ConfirmationSessionsStore {
	return s.confirmationSessionsStore
}
func (s *redisLiveStore) TreeSigingSessions() ports.TreeSigningSessionsStore {
	return s.treeSigningSessions
}
func (s *redisLiveStore) BoardingInputs() ports.BoardingInputsStore { return s.boardingInputsStore }

type redisLiveStore struct {
	txRequestsStore           ports.TxRequestsStore
	forfeitTxsStore           ports.ForfeitTxsStore
	offChainTxStore           ports.OffChainTxStore
	currentRoundStore         ports.CurrentRoundStore
	confirmationSessionsStore ports.ConfirmationSessionsStore
	treeSigningSessions       ports.TreeSigningSessionsStore
	boardingInputsStore       ports.BoardingInputsStore
}

type txRequestsStore struct{}

func NewTxRequestsStore() ports.TxRequestsStore { return &txRequestsStore{} }

func (s *txRequestsStore) Len() int64 { panic("not implemented") }
func (s *txRequestsStore) Push(request domain.TxRequest, boardingInputs []ports.BoardingInput, musig2Data *tree.Musig2) error {
	panic("not implemented")
}
func (s *txRequestsStore) Pop(num int64) []ports.TimedTxRequest { panic("not implemented") }
func (s *txRequestsStore) Update(request domain.TxRequest, musig2Data *tree.Musig2) error {
	panic("not implemented")
}
func (s *txRequestsStore) Delete(ids []string) error { panic("not implemented") }
func (s *txRequestsStore) DeleteAll() error          { panic("not implemented") }
func (s *txRequestsStore) DeleteVtxos()              { panic("not implemented") }
func (s *txRequestsStore) ViewAll(ids []string) ([]ports.TimedTxRequest, error) {
	panic("not implemented")
}
func (s *txRequestsStore) View(id string) (*domain.TxRequest, bool) { panic("not implemented") }
func (s *txRequestsStore) IncludesAny(outpoints []domain.VtxoKey) (bool, string) {
	panic("not implemented")
}

type forfeitTxsStore struct{}

func NewForfeitTxsStore() ports.ForfeitTxsStore { return &forfeitTxsStore{} }

func (s *forfeitTxsStore) Init(connectors tree.TxTree, requests []domain.TxRequest) error {
	panic("not implemented")
}
func (s *forfeitTxsStore) Sign(txs []string) error                          { panic("not implemented") }
func (s *forfeitTxsStore) Reset()                                           { panic("not implemented") }
func (s *forfeitTxsStore) Pop() ([]string, error)                           { panic("not implemented") }
func (s *forfeitTxsStore) AllSigned() bool                                  { panic("not implemented") }
func (s *forfeitTxsStore) Len() int                                         { panic("not implemented") }
func (s *forfeitTxsStore) GetConnectorsIndexes() map[string]domain.Outpoint { panic("not implemented") }

type offChainTxStore struct{}

func NewOffChainTxStore() ports.OffChainTxStore { return &offChainTxStore{} }

func (s *offChainTxStore) Add(offchainTx domain.OffchainTx)                 { panic("not implemented") }
func (s *offChainTxStore) Remove(virtualTxid string)                        { panic("not implemented") }
func (s *offChainTxStore) Get(virtualTxid string) (domain.OffchainTx, bool) { panic("not implemented") }
func (s *offChainTxStore) Includes(outpoint domain.VtxoKey) bool            { panic("not implemented") }

type confirmationSessionsStore struct{}

func NewConfirmationSessionsStore() ports.ConfirmationSessionsStore {
	return &confirmationSessionsStore{}
}

func (c *confirmationSessionsStore) Init(intentIDsHashes [][32]byte) { panic("not implemented") }

func (c *confirmationSessionsStore) Confirm(intentId string) error    { panic("not implemented") }
func (c *confirmationSessionsStore) Get() *ports.ConfirmationSessions { panic("not implemented") }
func (c *confirmationSessionsStore) Reset()                           { panic("not implemented") }
func (c *confirmationSessionsStore) Initialized() bool {
	//TODO implement me
	panic("implement me")
}
func (c *confirmationSessionsStore) SessionCompleted() <-chan struct{} { panic("not implemented") }

type currentRoundStore struct{}

func NewCurrentRoundStore() ports.CurrentRoundStore { return &currentRoundStore{} }

func (s *currentRoundStore) Upsert(fn func(m *domain.Round) *domain.Round) { panic("not implemented") }
func (s *currentRoundStore) Get() *domain.Round                            { panic("not implemented") }

type treeSigningSessionsStore struct{}

func NewTreeSigningSessionsStore() ports.TreeSigningSessionsStore { return &treeSigningSessionsStore{} }

func (s *treeSigningSessionsStore) New(roundId string, uniqueSignersPubKeys map[string]struct{}) *ports.MusigSigningSession {
	panic("not implemented")
}
func (s *treeSigningSessionsStore) Get(roundId string) (*ports.MusigSigningSession, bool) {
	panic("not implemented")
}
func (s *treeSigningSessionsStore) Delete(roundId string) { panic("not implemented") }
func (s *treeSigningSessionsStore) AddNonces(ctx context.Context, roundId string, pubkey string, nonces tree.TreeNonces) error {
	panic("not implemented")
}
func (s *treeSigningSessionsStore) AddSignatures(ctx context.Context, roundId string, pubkey string, nonces tree.TreePartialSigs) error {
	panic("not implemented")
}
func (s *treeSigningSessionsStore) NoncesCollected(roundId string) <-chan struct{} {
	panic("not implemented")
}
func (s *treeSigningSessionsStore) SignaturesCollected(roundId string) <-chan struct{} {
	panic("not implemented")
}

func NewBoardingInputsStore() ports.BoardingInputsStore { return &boardingInputsStore{} }

type boardingInputsStore struct{}

func (b *boardingInputsStore) Set(numOfInputs int) { panic("not implemented") }
func (b *boardingInputsStore) Get() int            { panic("not implemented") }
