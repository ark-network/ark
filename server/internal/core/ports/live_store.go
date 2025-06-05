package ports

import (
	"crypto/sha256"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"sync"
	"time"
)

type LiveStore interface {
	TxRequests() TxRequestsStore
	ForfeitTxs() ForfeitTxsStore
	OffchainTxs() OffChainTxStore
	CurrentRound() CurrentRoundStore
	ConfirmationSessions() ConfirmationSessionsStore
	TreeSigingSessions() TreeSigningSessionsStore
	BoardingInputs() BoardingInputsStore
}

type TxRequestsStore interface {
	Len() int64
	Push(request domain.TxRequest, boardingInputs []BoardingInput, musig2Data *tree.Musig2) error
	Pop(num int64) []TimedTxRequest
	Update(request domain.TxRequest, musig2Data *tree.Musig2) error
	Delete(ids []string) error
	DeleteAll() error
	DeleteVtxos()
	ViewAll(ids []string) ([]TimedTxRequest, error)
	View(id string) (*domain.TxRequest, bool)
	IncludesAny(outpoints []domain.VtxoKey) (bool, string)
}

type ForfeitTxsStore interface {
	Init(connectors tree.TxTree, requests []domain.TxRequest) error
	Sign(txs []string) error
	Reset()
	Pop() ([]string, error)
	AllSigned() bool
	Len() int
	GetConnectorsIndexes() map[string]domain.Outpoint
}

type OffChainTxStore interface {
	Add(offchainTx domain.OffchainTx)
	Remove(virtualTxid string)
	Get(virtualTxid string) (domain.OffchainTx, bool)
	Includes(outpoint domain.VtxoKey) bool
}

type CurrentRoundStore interface {
	Upsert(fn func(m *domain.Round) *domain.Round)
	Get() *domain.Round
}

type ConfirmationSessionsStore interface {
	Init(intentIDsHashes [][32]byte)
	Confirm(intentId string) error
	Get() *ConfirmationSessions
	Reset()
	Initialized() bool
}

type TreeSigningSessionsStore interface {
	New(roundId string, uniqueSignersPubKeys map[string]struct{}) *MusigSigningSession
	Get(roundId string) (*MusigSigningSession, bool)
	Delete(roundId string)
}

type BoardingInputsStore interface {
	Set(numOfInputs int)
	Get() int
}

type TimedTxRequest struct {
	domain.TxRequest
	BoardingInputs []BoardingInput
	Timestamp      time.Time
	Musig2Data     *tree.Musig2
}

func (t TimedTxRequest) HashID() [32]byte {
	return sha256.Sum256([]byte(t.Id))
}

// MusigSigningSession holds the state of ephemeral nonces and signatures in order to coordinate the signing of the tree
type MusigSigningSession struct {
	Lock        sync.Mutex
	NbCosigners int
	Cosigners   map[string]struct{}
	Nonces      map[secp256k1.PublicKey]tree.TreeNonces
	NonceDoneC  chan struct{}

	Signatures map[secp256k1.PublicKey]tree.TreePartialSigs
	SigDoneC   chan struct{}
}

type ConfirmationSessions struct {
	Lock sync.Mutex

	IntentsHashes       map[[32]byte]bool // hash --> confirmed
	NumIntents          int
	NumConfirmedIntents int
	ConfirmedC          chan struct{}
}
