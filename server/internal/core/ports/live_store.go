package ports

import (
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"sync"
	"time"
)

type LiveStore interface {
	TxRequest() TxRequestStore
	ForfeitTxs() ForfeitTxsStore
	OffChainTxInputs() OutpointStore
	RoundInputs() OutpointStore
	CurrentRound() CurrentRoundStore
	TreeSigingSessions() TreeSigningSessionsStore
	BoardingInputs() BoardingInputsStore
}

type TxRequestStore interface {
	Len() int64
	Push(request domain.TxRequest, boardingInputs []BoardingInput, musig2Data *tree.Musig2) error
	Pop(num int64) ([]domain.TxRequest, []BoardingInput, []*tree.Musig2)
	Update(request domain.TxRequest, musig2Data *tree.Musig2) error
	UpdatePingTimestamp(id string) error
	Delete(ids []string) error
	DeleteAll() error
	ViewAll(ids []string) ([]TimedTxRequest, error)
	View(id string) (*domain.TxRequest, bool)
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

type OutpointStore interface {
	Add(outpoints []domain.VtxoKey)
	Remove(outpoints []domain.VtxoKey)
	Includes(outpoint domain.VtxoKey) bool
	IncludesAny(outpoints []domain.VtxoKey) (bool, string)
}

type CurrentRoundStore interface {
	Upsert(fn func(m *domain.Round) *domain.Round)
	Get() *domain.Round
}

type TreeSigningSessionsStore interface {
	NewSession(roundId string, uniqueSignersPubKeys map[string]struct{}) *MusigSigningSession
	GetSession(roundId string) (*MusigSigningSession, bool)
	DeleteSession(roundId string)
}

type BoardingInputsStore interface {
	Set(numOfInputs int)
	Get() int
}

type TimedTxRequest struct {
	domain.TxRequest
	BoardingInputs []BoardingInput
	Timestamp      time.Time
	PingTimestamp  time.Time
	Musig2Data     *tree.Musig2
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
