package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	UndefinedStage RoundStage = iota
	RegistrationStage
	FinalizationStage

	dustAmount = 450
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
	Payments          map[string]Payment
	Txid              string
	TxHex             string
	ForfeitTxs        []string
	CongestionTree    []string
	Connectors        []string
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
	case RoundStarted:
		r.Stage.Code = RegistrationStage
		r.Id = e.Id
		r.StartingTimestamp = e.Timestamp
	case RoundFinalizationStarted:
		r.Stage.Code = FinalizationStage
		r.CongestionTree = append([]string{}, e.CongestionTree...)
		r.Connectors = append([]string{}, e.Connectors...)
		r.TxHex = e.PoolTx
	case RoundFinalized:
		r.Stage.Ended = true
		r.Txid = e.Txid
		r.ForfeitTxs = append([]string{}, e.ForfeitTxs...)
		r.EndingTimestamp = e.Timestamp
	case RoundFailed:
		r.Stage.Failed = true
		r.EndingTimestamp = e.Timestamp
	case PaymentsRegistered:
		if r.Payments == nil {
			r.Payments = make(map[string]Payment)
		}
		for _, p := range e.Payments {
			r.Payments[p.Id] = p
		}
	case PaymentsClaimed:
		for _, p := range e.Payments {
			r.Payments[p.Id] = Payment{
				Id:        p.Id,
				Inputs:    r.Payments[p.Id].Inputs,
				Receivers: p.Receivers,
			}
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

	event := RoundStarted{
		Id:        r.Id,
		Timestamp: time.Now().Unix(),
	}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) StartFinalization(connectors, tree []string, poolTx string) ([]RoundEvent, error) {
	if r.Stage.Code != RegistrationStage || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to start payment finalization")
	}

	event := RoundFinalizationStarted{
		Id:             r.Id,
		CongestionTree: tree,
		Connectors:     connectors,
		PoolTx:         poolTx,
	}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) EndFinalization(forfeitTxs []string, txid string) ([]RoundEvent, error) {
	if r.Stage.Code != FinalizationStage || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to end payment finalization")
	}
	if r.Stage.Ended {
		return nil, fmt.Errorf("payment finalization already ended")
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
		Err:       err,
		Timestamp: time.Now().Unix(),
	}
	r.raise(event)

	return []RoundEvent{event}
}

func (r *Round) RegisterPayments(payments []Payment) ([]RoundEvent, error) {
	if !r.IsStarted() {
		return nil, fmt.Errorf("not in a valid stage to register payments")
	}
	if len(payments) <= 0 {
		return nil, fmt.Errorf("missing payments to register")
	}
	for _, p := range payments {
		ignoreOuts := true
		if err := p.validate(ignoreOuts); err != nil {
			return nil, err
		}
	}

	event := PaymentsRegistered{
		Id:       r.Id,
		Payments: payments,
	}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) ClaimPaymenys(payments []Payment) ([]RoundEvent, error) {
	if r.Stage.Code != RegistrationStage || r.IsFailed() {
		return nil, fmt.Errorf("not in a valid stage to register inputs")
	}
	if r.Stage.Ended {
		return nil, fmt.Errorf("payment registration already ended")
	}
	for _, p := range payments {
		if err := p.validate(false); err != nil {
			return nil, fmt.Errorf("invalid payment: %s", err)
		}
		if _, ok := r.Payments[p.Id]; !ok {
			return nil, fmt.Errorf("payment %s not registered", p.Id)
		}
	}

	event := PaymentsClaimed{
		Id:       r.Id,
		Payments: payments,
	}
	r.raise(event)

	return []RoundEvent{event}, nil
}

func (r *Round) IsStarted() bool {
	return !r.IsFailed() && r.Stage.Code == RegistrationStage
}

func (r *Round) IsEnded() bool {
	return !r.IsFailed() && r.Stage.Code == FinalizationStage && r.Stage.Ended
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
