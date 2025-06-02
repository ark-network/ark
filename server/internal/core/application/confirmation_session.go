package application

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

// confirmationSession holds the state of the confirmation process
type confirmationSession struct {
	lock sync.Mutex

	intentsHashes       map[[32]byte]bool // hash --> confirmed
	numIntents          int
	numConfirmedIntents int
	confirmedC          chan struct{}
}

func newConfirmationSession(intentsHashes [][32]byte) *confirmationSession {
	hashes := make(map[[32]byte]bool)
	for _, hash := range intentsHashes {
		hashes[hash] = false
	}

	return &confirmationSession{
		intentsHashes:       hashes,
		numIntents:          len(intentsHashes),
		numConfirmedIntents: 0,
		confirmedC:          make(chan struct{}),
		lock:                sync.Mutex{},
	}
}

func (s *confirmationSession) confirm(intentId string) error {
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
