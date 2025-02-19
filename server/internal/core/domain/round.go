package domain

import (
	"fmt"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/google/uuid"
)

const (
	UndefinedStage RoundStage = iota
	RegistrationStage
	FinalizationStage
)

type RoundStage int

func (s RoundStage) String() string {
	switch s {
	case RegistrationStage:
		return "REGISTRATION_STAGE"
	case FinalizationStage:
		return "FINALIZATION_STAGE"
	default:
		return "UNDEFINED_STAGE"
	}
}

type Stage struct {
	Code   RoundStage
	Ended  bool
	Failed bool
}

type Round struct {
	Id                string
	StartingTimestamp int64
	EndingTimestamp   int64
	Stage             Stage
	TxRequests        map[string]TxRequest
	Txid              string
	UnsignedTx        string
	ForfeitTxs        []string
	VtxoTree          tree.TxTree
	Connectors        tree.TxTree
	ConnectorAddress  string
	DustAmount        uint64
	Version           uint
	Swept             bool // true if all the vtxos are vtxo.Swept or vtxo.Redeemed
	changes           []RoundEvent
}

func NewRound(dustAmount uint64) *Round {
	return &Round{
		Id:         uuid.New().String(),
		DustAmount: dustAmount,
		TxRequests: make(map[string]TxRequest),
		changes:    make([]RoundEvent, 0),
	}
}

func NewRoundFromEvents(events []RoundEvent) *Round {
	r := &Round{}

	for _, event := range events {
		r.On(event, true)
	}

	r.changes = append([]RoundEvent{}, events...)

	return r
}

func (r *Round) Events() []RoundEvent {
	return r.changes
}

func (r *Round) On(event RoundEvent, replayed bool) {
	switch e := event.(type) {
	case RoundStarted:
		r.Stage.Code = RegistrationStage
		r.Id = e.Id
		r.StartingTimestamp = e.Timestamp
	case RoundFinalizationStarted:
		r.Stage.Code = FinalizationStage
		r.VtxoTree = e.VtxoTree
		r.Connectors = e.Connectors
		r.ConnectorAddress = e.ConnectorAddress
		r.UnsignedTx = e.RoundTx
	case RoundFinalized:
		r.Stage.Ended = true
		r.Txid = e.Txid
		r.ForfeitTxs = append([]string{}, e.ForfeitTxs...)
		r.EndingTimestamp = e.Timestamp
	case RoundFailed:
		r.Stage.Failed = true
		r.EndingTimestamp = e.Timestamp
	case TxRequestsRegistered:
		if r.TxRequests == nil {
			r.TxRequests = make(map[string]TxRequest)
		}
		for _, p := range e.TxRequests {
			r.TxRequests[p.Id] = p
		}
	}

	if replayed {
		r.Version++
	}
}

func (r *Round) StartRegistration() ([]RoundEvent, error) {
	empty := Stage{}
	if r.Stage != empty {
		return nil, fmt.Errorf("not in a valid stage to start tx requests registration")
	}

	event := RoundStarted{
		Id:        r.Id,
		Timestamp: time.Now().Unix(),
	}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) RegisterTxRequests(txRequests []TxRequest) ([]RoundEvent, error) {
	if r.Stage.Code != RegistrationStage || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to register tx requests")
	}
	if len(txRequests) <= 0 {
		return nil, fmt.Errorf("missing tx requests to register")
	}
	for _, request := range txRequests {
		if err := request.validate(false); err != nil {
			return nil, err
		}
	}

	event := TxRequestsRegistered{
		Id:         r.Id,
		TxRequests: txRequests,
	}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) StartFinalization(
	connectorAddress string,
	connectors tree.TxTree,
	vtxoTree tree.TxTree,
	roundTx string,
	connectorsIndex map[string]Outpoint,
) ([]RoundEvent, error) {
	if len(roundTx) <= 0 {
		return nil, fmt.Errorf("missing unsigned round tx")
	}
	if r.Stage.Code != RegistrationStage || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to start finalization")
	}
	if len(r.TxRequests) <= 0 {
		return nil, fmt.Errorf("no tx requests registered")
	}

	event := RoundFinalizationStarted{
		Id:               r.Id,
		VtxoTree:         vtxoTree,
		Connectors:       connectors,
		ConnectorAddress: connectorAddress,
		RoundTx:          roundTx,
		ConnectorsIndex:  connectorsIndex,
	}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) EndFinalization(forfeitTxs []string, txid string) ([]RoundEvent, error) {
	if len(forfeitTxs) <= 0 {
		for _, request := range r.TxRequests {
			if len(request.Inputs) > 0 {
				return nil, fmt.Errorf("missing list of signed forfeit txs")
			}
		}
	}
	if len(txid) <= 0 {
		return nil, fmt.Errorf("missing round txid")
	}
	if r.Stage.Code != FinalizationStage || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to end finalization")
	}
	if r.Stage.Ended {
		return nil, fmt.Errorf("round already finalized")
	}
	if forfeitTxs == nil {
		forfeitTxs = make([]string, 0)
	}

	event := RoundFinalized{
		Id:         r.Id,
		Txid:       txid,
		ForfeitTxs: forfeitTxs,
		Timestamp:  time.Now().Unix(),
	}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) Fail(err error) []RoundEvent {
	if r.Stage.Failed {
		return nil
	}
	event := RoundFailed{
		Id:        r.Id,
		Err:       err.Error(),
		Timestamp: time.Now().Unix(),
	}
	r.raise(event)

	return []RoundEvent{event}
}

func (r *Round) IsStarted() bool {
	empty := Stage{}
	return !r.IsFailed() && !r.IsEnded() && r.Stage != empty
}

func (r *Round) IsEnded() bool {
	return !r.IsFailed() && r.Stage.Code == FinalizationStage && r.Stage.Ended
}

func (r *Round) IsFailed() bool {
	return r.Stage.Failed
}

func (r *Round) TotalInputAmount() uint64 {
	totInputs := 0
	for _, request := range r.TxRequests {
		totInputs += len(request.Inputs)
	}
	return uint64(totInputs * int(r.DustAmount))
}

func (r *Round) TotalOutputAmount() uint64 {
	tot := uint64(0)
	for _, request := range r.TxRequests {
		tot += request.TotalOutputAmount()
	}
	return tot
}

func (r *Round) Sweep() {
	r.Swept = true
}

func (r *Round) raise(event RoundEvent) {
	if r.changes == nil {
		r.changes = make([]RoundEvent, 0)
	}
	r.changes = append(r.changes, event)
	r.On(event, false)
}
