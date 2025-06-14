package inmemorylivestore

import (
	"github.com/ark-network/ark/server/internal/core/ports"
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
