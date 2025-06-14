package redislivestore

import (
	"github.com/redis/go-redis/v9"

	"github.com/ark-network/ark/server/internal/core/ports"
)

func NewLiveStore(rdb *redis.Client, builder ports.TxBuilder, numOfRetries int) ports.LiveStore {
	return &redisLiveStore{
		txRequestsStore:           NewTxRequestsStore(rdb, numOfRetries),
		forfeitTxsStore:           NewForfeitTxsStore(rdb, builder),
		offChainTxStore:           NewOffChainTxStore(rdb),
		currentRoundStore:         NewCurrentRoundStore(rdb, numOfRetries),
		confirmationSessionsStore: NewConfirmationSessionsStore(rdb, numOfRetries),
		treeSigningSessions:       NewTreeSigningSessionsStore(rdb),
		boardingInputsStore:       NewBoardingInputsStore(rdb),
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
