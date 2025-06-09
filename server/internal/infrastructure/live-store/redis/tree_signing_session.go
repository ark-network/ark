// Redis-backed implementation of treeSigningSessionsStore. All session state is stored in Redis hashes.
// Notification channels for nonces and signatures collection are implemented via goroutines that poll Redis state.
// For true distributed notification, consider using Redis Pub/Sub.

package redislivestore

import (
	"context"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/redis/go-redis/v9"
)

const (
	treeSessMetaKeyFmt   = "treeSignSess:%s:meta"
	treeSessNoncesKeyFmt = "treeSignSess:%s:nonces"
	treeSessSigsKeyFmt   = "treeSignSess:%s:sigs"
)

type treeSigningSessionsStore struct {
	rdb          *redis.Client
	nonceCh      chan struct{}
	sigsCh       chan struct{}
	pollInterval time.Duration
}

func NewTreeSigningSessionsStore(rdb *redis.Client) ports.TreeSigningSessionsStore {
	return &treeSigningSessionsStore{
		rdb:          rdb,
		pollInterval: 100 * time.Millisecond,
	}
}

func (s *treeSigningSessionsStore) New(roundId string, uniqueSignersPubKeys map[string]struct{}) *ports.MusigSigningSession {
	ctx := context.Background()
	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	cosignersBytes, _ := json.Marshal(uniqueSignersPubKeys)
	meta := map[string]interface{}{
		"Cosigners":   cosignersBytes,
		"NbCosigners": len(uniqueSignersPubKeys) + 1, // server included
	}
	s.rdb.HSet(ctx, metaKey, meta)

	s.nonceCh = make(chan struct{})
	s.sigsCh = make(chan struct{})
	go s.watchNoncesCollected(roundId)
	go s.watchSigsCollected(roundId)

	return &ports.MusigSigningSession{
		Cosigners:   uniqueSignersPubKeys,
		NbCosigners: len(uniqueSignersPubKeys) + 1,
		Nonces:      make(map[string]tree.TreeNonces),
		Signatures:  make(map[string]tree.TreePartialSigs),
	}
}

func (s *treeSigningSessionsStore) Get(roundId string) (*ports.MusigSigningSession, bool) {
	ctx := context.Background()

	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	meta, err := s.rdb.HGetAll(ctx, metaKey).Result()
	if err != nil || len(meta) == 0 {
		return nil, false
	}

	var cosigners map[string]struct{}
	if err := json.Unmarshal([]byte(meta["Cosigners"]), &cosigners); err != nil {
		return nil, false
	}
	nbCosigners := 0
	fmt.Sscanf(meta["NbCosigners"], "%d", &nbCosigners)

	noncesKey := fmt.Sprintf(treeSessNoncesKeyFmt, roundId)
	noncesMap, _ := s.rdb.HGetAll(ctx, noncesKey).Result()
	nonces := make(map[string]tree.TreeNonces)
	for pub, val := range noncesMap {
		var n tree.TreeNonces
		json.Unmarshal([]byte(val), &n)
		nonces[pub] = n
	}

	sigsKey := fmt.Sprintf(treeSessSigsKeyFmt, roundId)
	sigsMap, _ := s.rdb.HGetAll(ctx, sigsKey).Result()
	sigs := make(map[string]tree.TreePartialSigs)
	for pub, val := range sigsMap {
		var sgs tree.TreePartialSigs
		json.Unmarshal([]byte(val), &sgs)
		sigs[pub] = sgs
	}

	sess := &ports.MusigSigningSession{
		Cosigners:   cosigners,
		NbCosigners: nbCosigners,
		Nonces:      nonces,
		Signatures:  sigs,
	}
	return sess, true
}

func (s *treeSigningSessionsStore) Delete(roundId string) {
	ctx := context.Background()
	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	noncesKey := fmt.Sprintf(treeSessNoncesKeyFmt, roundId)
	sigsKey := fmt.Sprintf(treeSessSigsKeyFmt, roundId)
	s.rdb.Del(ctx, metaKey, noncesKey, sigsKey)
	if s.nonceCh != nil {
		close(s.nonceCh)
		s.nonceCh = nil
	}
	if s.sigsCh != nil {
		close(s.sigsCh)
		s.sigsCh = nil
	}
}

func (s *treeSigningSessionsStore) AddNonces(ctx context.Context, roundId string, pubkey string, nonces tree.TreeNonces) error {
	noncesKey := fmt.Sprintf(treeSessNoncesKeyFmt, roundId)
	val, _ := json.Marshal(nonces)
	if err := s.rdb.HSet(ctx, noncesKey, pubkey, val).Err(); err != nil {
		return err
	}
	return nil
}

func (s *treeSigningSessionsStore) AddSignatures(ctx context.Context, roundId string, pubkey string, sigs tree.TreePartialSigs) error {
	sigsKey := fmt.Sprintf(treeSessSigsKeyFmt, roundId)
	val, _ := json.Marshal(sigs)
	if err := s.rdb.HSet(ctx, sigsKey, pubkey, val).Err(); err != nil {
		return err
	}
	return nil
}

func (s *treeSigningSessionsStore) NoncesCollected(roundId string) <-chan struct{} {
	return s.nonceCh
}

func (s *treeSigningSessionsStore) SignaturesCollected(roundId string) <-chan struct{} {
	return s.sigsCh
}

func (s *treeSigningSessionsStore) watchNoncesCollected(roundId string) {
	ctx := context.Background()
	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	noncesKey := fmt.Sprintf(treeSessNoncesKeyFmt, roundId)
	for {
		meta, err := s.rdb.HGetAll(ctx, metaKey).Result()
		if err != nil || len(meta) == 0 {
			continue
		}
		nbCosigners := 0
		fmt.Sscanf(meta["NbCosigners"], "%d", &nbCosigners)
		noncesMap, _ := s.rdb.HGetAll(ctx, noncesKey).Result()
		log.Debugf("nonces collected: %d/%d", len(noncesMap), nbCosigners-1)
		if len(noncesMap) == nbCosigners-1 {
			if s.nonceCh != nil {
				close(s.nonceCh)
				s.nonceCh = nil
			}
			return
		}
	}
}

func (s *treeSigningSessionsStore) watchSigsCollected(roundId string) {
	ctx := context.Background()
	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	sigsKey := fmt.Sprintf(treeSessSigsKeyFmt, roundId)
	for {
		meta, err := s.rdb.HGetAll(ctx, metaKey).Result()
		if err != nil || len(meta) == 0 {
			continue
		}
		nbCosigners := 0
		fmt.Sscanf(meta["NbCosigners"], "%d", &nbCosigners)
		sigsMap, _ := s.rdb.HGetAll(ctx, sigsKey).Result()
		log.Debugf("sigs collected: %d/%d", len(sigsMap), nbCosigners-1)
		if len(sigsMap) == nbCosigners-1 {
			if s.sigsCh != nil {
				close(s.sigsCh)
				s.sigsCh = nil
			}
			return
		}
	}
}
