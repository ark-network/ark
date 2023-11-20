package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	UndefinedStage RoundStage = iota
	PaymentRegistrationStage
	PaymentFinalizationStage

	dustAmount = 450
)

type RoundStage int

func (s RoundStage) String() string {
	switch s {
	case PaymentRegistrationStage:
		return "REGISTRATION_STAGE"
	case PaymentFinalizationStage:
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
	Payments          map[string]Payment
	Txid              string
	ForfeitTxs        []string
	CongestionTree    []string
	Version           uint
	Changes           []RoundEvent
}

func NewRound() *Round {
	return &Round{
		Id:       uuid.New().String(),
		Payments: make(map[string]Payment),
		Changes:  make([]RoundEvent, 0),
	}
}

func NewRoundFromEvents(events []RoundEvent) *Round {
	r := &Round{}

	for _, event := range events {
		r.On(event, true)
	}

	r.Changes = append([]RoundEvent{}, events...)

	return r
}

func (r *Round) On(event RoundEvent, replayed bool) {
	switch e := event.(type) {
	case PaymentRegistrationStarted:
		r.Stage.Code = PaymentRegistrationStage
		r.Id = e.Id
		r.StartingTimestamp = e.Timestamp
	case PaymentRegistrationEnded:
		r.Stage.Ended = true
		r.ForfeitTxs = append([]string{}, e.ForfeitTxs...)
		r.CongestionTree = append([]string{}, e.CongestionTree...)
	case PaymentFinalizationStarted:
		r.Stage.Code = PaymentFinalizationStage
	case PaymentFinalizationEnded:
		r.Stage.Ended = true
		r.Txid = e.Txid
	case RoundFailed:
		r.Stage.Failed = true
	case InputsRegistered:
		if r.Payments == nil {
			r.Payments = make(map[string]Payment)
		}
		r.Payments[e.PaymentId] = Payment{
			Id:     e.PaymentId,
			Inputs: e.PaymentInputs,
		}
	case OutputsRegistered:
		r.Payments[e.PaymentId] = Payment{
			Id:        e.PaymentId,
			Inputs:    r.Payments[e.PaymentId].Inputs,
			Receivers: e.PaymentOutputs,
		}
	}

	if replayed {
		r.Version++
	}
}

func (r *Round) StartRegistration() ([]RoundEvent, error) {
	empty := Stage{}
	if r.Stage != empty {
		return nil, fmt.Errorf("not in a valid stage to start payment registration")
	}

	event := PaymentRegistrationStarted{
		Id:        r.Id,
		Timestamp: time.Now().Unix(),
	}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) EndRegistration(txs, tree []string) ([]RoundEvent, error) {
	if r.Stage.Code != PaymentRegistrationStage || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to end payment registration")
	}
	if r.Stage.Ended {
		return nil, fmt.Errorf("payment registration already ended")
	}

	event := PaymentRegistrationEnded{
		Id:             r.Id,
		ForfeitTxs:     txs,
		CongestionTree: tree,
	}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) StartFinalization() ([]RoundEvent, error) {
	if r.Stage.Code != PaymentRegistrationStage || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to start payment finalization")
	}
	if !r.Stage.Ended {
		return nil, fmt.Errorf("payment registration did not ended yet")
	}
	event := PaymentFinalizationStarted{Id: r.Id}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) EndFinalization(txid string) ([]RoundEvent, error) {
	if r.Stage.Code != PaymentFinalizationStage || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to end payment finalization")
	}
	if r.Stage.Ended {
		return nil, fmt.Errorf("payment finalization already ended")
	}
	event := PaymentFinalizationEnded{
		Id:   r.Id,
		Txid: txid,
	}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) Fail(err error) []RoundEvent {
	if r.Stage.Failed {
		return nil
	}
	event := RoundFailed{Id: r.Id, Err: err}
	r.raise(event)

	return []RoundEvent{event}
}

func (r *Round) RegisterInputs(id string, ins []Vtxo) ([]RoundEvent, error) {
	if r.Stage.Code != PaymentRegistrationStage || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to register inputs")
	}
	if r.Stage.Ended {
		return nil, fmt.Errorf("payment registration already ended")
	}

	event := InputsRegistered{
		Id:            r.Id,
		PaymentId:     id,
		PaymentInputs: ins,
	}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) RegisterOutputs(id string, outs []Receiver) ([]RoundEvent, error) {
	if r.Stage.Code != PaymentRegistrationStage || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to register inputs")
	}
	if r.Stage.Ended {
		return nil, fmt.Errorf("payment registration already ended")
	}

	event := OutputsRegistered{
		Id:             r.Id,
		PaymentId:      id,
		PaymentOutputs: outs,
	}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) IsStarted() bool {
	empty := Stage{}
	return !r.IsFailed() && (r.Stage != empty && !r.IsEnded())
}

func (r *Round) IsEnded() bool {
	return !r.IsFailed() && (r.Stage.Code == PaymentFinalizationStage && r.Stage.Ended)
}

func (r *Round) IsFailed() bool {
	return r.Stage.Failed
}

func (r *Round) TotInputAmount() uint64 {
	return uint64(len(r.Payments) * dustAmount)
}

func (r *Round) TotOutputAmount() uint64 {
	tot := uint64(0)
	for _, p := range r.Payments {
		tot += p.TotOutputAmount()
	}
	return tot
}

func (r *Round) raise(event RoundEvent) {
	if r.Changes == nil {
		r.Changes = make([]RoundEvent, 0)
	}
	r.Changes = append(r.Changes, event)
	r.On(event, false)
}
