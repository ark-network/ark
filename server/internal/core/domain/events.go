package domain

import "github.com/ark-network/ark/common/tree"

type RoundEvent interface {
	IsEvent()
}

func (r RoundStarted) IsEvent()             {}
func (r RoundFinalizationStarted) IsEvent() {}
func (r RoundFinalized) IsEvent()           {}
func (r RoundFailed) IsEvent()              {}
func (r PaymentsRegistered) IsEvent()       {}

type RoundStarted struct {
	Id        string
	Timestamp int64
}

type RoundFinalizationStarted struct {
	Id               string
	CongestionTree   tree.CongestionTree // BTC: signed
	Connectors       []string
	ConnectorAddress string
	RoundTx          string
	MinRelayFeeRate  int64
}

type RoundFinalized struct {
	Id         string
	Txid       string
	ForfeitTxs []string
	Timestamp  int64
}

type RoundFailed struct {
	Id        string
	Err       string
	Timestamp int64
}

type PaymentsRegistered struct {
	Id       string
	Payments []Payment
}
