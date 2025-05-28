package domain

import (
	"fmt"
	"time"
)

const (
	OffchainTxUndefinedStage OffchainTxStage = iota
	OffchainTxRequestedStage
	OffchainTxAcceptedStage
	OffchainTxFinalizedStage
)

type OffchainTxStage int

func (s OffchainTxStage) String() string {
	switch s {
	case OffchainTxRequestedStage:
		return "OFFCHAIN_TX_REQUESTED_STAGE"
	case OffchainTxAcceptedStage:
		return "OFFCHAIN_TX_ACCEPTED_STAGE"
	case OffchainTxFinalizedStage:
		return "OFFCHAIN_TX_FINALIZED_STAGE"
	default:
		return "OFFCHAIN_TX_UNDEFINED_STAGE"
	}
}

type Tx struct {
	Txid string
	Str  string
}

type OffchainTx struct {
	Stage              Stage
	StartingTimestamp  int64
	EndingTimestamp    int64
	VirtualTxid        string
	VirtualTx          string
	CheckpointTxs      map[string]string //tx/hex
	CommitmentTxids    map[string]string //checkpointTxId/CommitmentTxId
	RootCommitmentTxId string
	ExpiryTimestamp    int64
	FailReason         string
	Version            uint
	changes            []Event
}

func NewOffchainTx() *OffchainTx {
	return &OffchainTx{
		changes: make([]Event, 0),
	}
}

func NewOffchainTxFromEvents(events []Event) *OffchainTx {
	s := &OffchainTx{}

	for _, event := range events {
		s.on(event, true)
	}

	s.changes = append([]Event{}, events...)

	return s
}

func (s *OffchainTx) Request(
	virtualTxid, virtualTx string, unsignedCheckpointTxs map[string]string,
) (Event, error) {
	if s.IsFailed() || s.Stage.Code != int(OffchainTxUndefinedStage) {
		return nil, fmt.Errorf("not in a valid stage to request offchain tx")
	}
	if virtualTxid == "" {
		return nil, fmt.Errorf("missing virtual txid")
	}
	if virtualTx == "" {
		return nil, fmt.Errorf("missing virtual tx")
	}
	if len(unsignedCheckpointTxs) == 0 {
		return nil, fmt.Errorf("missing unsigned checkpoint txs")
	}

	event := OffchainTxRequested{
		Id:                    virtualTxid,
		VirtualTx:             virtualTx,
		UnsignedCheckpointTxs: unsignedCheckpointTxs,
		StartingTimestamp:     time.Now().Unix(),
	}
	s.raise(event)
	return event, nil
}

func (s *OffchainTx) Accept(
	finalVirtualTx string, signedCheckpointTxs map[string]string,
	commitmentTxsByCheckpointTxid map[string]string, rootCommitmentTx string, expiryTimestamp int64,
) (Event, error) {
	if finalVirtualTx == "" {
		return nil, fmt.Errorf("missing final virtual tx")
	}
	if len(signedCheckpointTxs) == 0 {
		return nil, fmt.Errorf("missing signed checkpoint txs")
	}
	if len(signedCheckpointTxs) != len(s.CheckpointTxs) {
		return nil, fmt.Errorf("invalid number of signed checkpoint txs, expected %d, got %d", len(s.CheckpointTxs), len(signedCheckpointTxs))
	}
	if len(commitmentTxsByCheckpointTxid) == 0 {
		return nil, fmt.Errorf("missing commitment txids")
	}
	if rootCommitmentTx == "" {
		return nil, fmt.Errorf("missing root commitment txid")
	}
	if !s.IsRequested() {
		return nil, fmt.Errorf("not in a valid stage to accept offchain tx")
	}
	if expiryTimestamp <= 0 {
		return nil, fmt.Errorf("missing expiry timestamp")
	}
	event := OffchainTxAccepted{
		Id:                  s.VirtualTxid,
		FinalVirtualTx:      finalVirtualTx,
		SignedCheckpointTxs: signedCheckpointTxs,
		CommitmentTxids:     commitmentTxsByCheckpointTxid,
		RootCommitmentTxid:  rootCommitmentTx,
		ExpiryTimestamp:     expiryTimestamp,
	}
	s.raise(event)
	return event, nil
}

func (s *OffchainTx) Finalize(
	finalCheckpointTxs map[string]string,
) (Event, error) {
	if len(finalCheckpointTxs) == 0 {
		return nil, fmt.Errorf("missing final checkpoint txs")
	}
	if len(finalCheckpointTxs) != len(s.CheckpointTxs) {
		return nil, fmt.Errorf("invalid number of final checkpoint txs, expected %d, got %d", len(s.CheckpointTxs), len(finalCheckpointTxs))
	}
	if !s.IsAccepted() {
		return nil, fmt.Errorf("not in a valid stage to finalize offchain tx")
	}

	event := OffchainTxFinalized{
		Id:                 s.VirtualTxid,
		FinalCheckpointTxs: finalCheckpointTxs,
		Timestamp:          time.Now().Unix(),
	}
	s.raise(event)
	return event, nil
}

func (s *OffchainTx) Fail(err error) Event {
	event := OffchainTxFailed{
		Id:        s.VirtualTxid,
		Reason:    err.Error(),
		Timestamp: time.Now().Unix(),
	}
	s.raise(event)
	return event
}

func (s *OffchainTx) RootCommitmentTxid() string {
	return s.RootCommitmentTxId
}

func (s *OffchainTx) Events() []Event {
	return s.changes
}

func (s *OffchainTx) IsRequested() bool {
	return !s.IsFailed() && s.Stage.Code == int(OffchainTxRequestedStage)
}

func (s *OffchainTx) IsAccepted() bool {
	return !s.IsFailed() && s.Stage.Code == int(OffchainTxAcceptedStage)
}

func (s *OffchainTx) IsFinalized() bool {
	return !s.IsFailed() && s.Stage.Code == int(OffchainTxFinalizedStage)
}

func (s *OffchainTx) IsFailed() bool {
	return s.Stage.Failed
}

func (s *OffchainTx) on(event Event, replayed bool) {
	switch e := event.(type) {
	case OffchainTxRequested:
		s.Stage.Code = int(OffchainTxRequestedStage)
		s.VirtualTxid = e.Id
		s.VirtualTx = e.VirtualTx
		s.CheckpointTxs = e.UnsignedCheckpointTxs
		s.StartingTimestamp = e.StartingTimestamp
	case OffchainTxAccepted:
		s.Stage.Code = int(OffchainTxAcceptedStage)
		s.VirtualTx = e.FinalVirtualTx
		s.CheckpointTxs = e.SignedCheckpointTxs
		s.CommitmentTxids = e.CommitmentTxids
		s.RootCommitmentTxId = e.RootCommitmentTxid
		s.ExpiryTimestamp = e.ExpiryTimestamp
	case OffchainTxFinalized:
		s.Stage.Code = int(OffchainTxFinalizedStage)
		s.CheckpointTxs = e.FinalCheckpointTxs
		s.EndingTimestamp = e.Timestamp
	case OffchainTxFailed:
		s.Stage.Failed = true
		s.FailReason = e.Reason
		s.EndingTimestamp = e.Timestamp
	}

	if replayed {
		s.Version++
	}
}

func (s *OffchainTx) raise(event Event) {
	if s.changes == nil {
		s.changes = make([]Event, 0)
	}
	s.changes = append(s.changes, event)
	s.on(event, false)
}
