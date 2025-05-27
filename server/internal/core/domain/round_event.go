package domain

import (
	"github.com/ark-network/ark/common/tree"
)

const RoundTopic = "round"

func (r RoundStarted) GetTopic() string             { return RoundTopic }
func (r RoundFinalizationStarted) GetTopic() string { return RoundTopic }
func (r RoundFinalized) GetTopic() string           { return RoundTopic }
func (r RoundFailed) GetTopic() string              { return RoundTopic }
func (r TxRequestsRegistered) GetTopic() string     { return RoundTopic }

type RoundStarted struct {
	Id        string
	Timestamp int64
}

type RoundFinalizationStarted struct {
	Id                 string
	VtxoTree           tree.TxTree
	Connectors         tree.TxTree
	ConnectorAddress   string
	RoundTx            string
	ConnectorsIndex    map[string]Outpoint
	VtxoTreeExpiration int64
}

type RoundFinalized struct {
	Id                string
	Txid              string
	ForfeitTxs        []ForfeitTx
	FinalCommitmentTx string
	Timestamp         int64
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
