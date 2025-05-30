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
	OffChainTxInputs() OffChainTxInputsStore
	RoundInputs() RoundInputsStore
	CurrentRound() CurrentRoundStore
	TreeSigingSessions() TreeSigningSessionsStore
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
}

type OffChainTxInputsStore interface {
	OutpointStore
}

type RoundInputsStore interface {
	OutpointStore
}

type OutpointStore interface {
	Add(outpoints []domain.VtxoKey)
	Remove(outpoints []domain.VtxoKey)
	Includes(outpoint domain.VtxoKey) bool
	IncludesAny(outpoints []domain.VtxoKey) (bool, string)
}

type CurrentRoundStore interface {
	Upsert(round *domain.Round) error
	Get() (*domain.Round, error)
}

type TreeSigningSessionsStore interface {
	NewSession(roundId string, uniqueSignersPubKeys map[string]struct{}) (*MusigSigningSession, error)
	GetSession(roundId string) (*MusigSigningSession, error)
	DeleteSession(roundId string)
}

type TimedTxRequest struct {
	domain.TxRequest
	BoardingInputs []BoardingInput
	Timestamp      time.Time
	PingTimestamp  time.Time
	Musig2Data     *tree.Musig2
}

type MusigSigningSession struct {
	Lock        sync.Mutex
	NbCosigners int
	Cosigners   map[string]struct{}
	Nonces      map[*secp256k1.PublicKey]tree.TreeNonces
	NonceDoneC  chan struct{}

	Signatures map[*secp256k1.PublicKey]tree.TreePartialSigs
	SigDoneC   chan struct{}
}
