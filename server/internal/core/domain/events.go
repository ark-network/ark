package domain

import "github.com/ark-network/ark/common/tree"

type RoundEvent interface {
	IsEvent()
}

func (r RoundStarted) IsEvent()             {}
func (r RoundFinalizationStarted) IsEvent() {}
func (r RoundFinalized) IsEvent()           {}
func (r RoundFailed) IsEvent()              {}
func (r TxRequestsRegistered) IsEvent()     {}

type RoundStarted struct {
	Id        string
	Timestamp int64
}

type RoundFinalizationStarted struct {
	Id               string
	VtxoTree         tree.TxTree
	Connectors       tree.TxTree
	ConnectorAddress string
	RoundTx          string
	MinRelayFeeRate  int64
	ConnectorsIndex  map[string]Outpoint
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

type TxRequestsRegistered struct {
	Id         string
	TxRequests []TxRequest
}
