package domain

import (
	"fmt"
	"strconv"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type ConfigData struct {
	AspUrl                     string
	AspPubkey                  *secp256k1.PublicKey
	WalletType                 string
	ClientType                 string
	Network                    common.Network
	RoundLifetime              int64
	RoundInterval              int64
	UnilateralExitDelay        int64
	Dust                       uint64
	BoardingDescriptorTemplate string
	ExplorerURL                string
	ForfeitAddress             string
	ListenTransactionStream    bool
}

type Vtxo struct {
	Txid                    string
	VOut                    uint32
	Amount                  uint64
	RoundTxid               string
	ExpiresAt               *time.Time
	RedeemTx                string
	UnconditionalForfeitTxs []string
	Pending                 bool
	SpentBy                 string
	Spent                   bool
}

func (v Vtxo) Key() string {
	return fmt.Sprintf("%s:%s", v.Txid, strconv.Itoa(int(v.VOut)))
}

const (
	TxSent     TxType = "sent"
	TxReceived TxType = "received"
)

type TxType string

type Transaction struct {
	BoardingTxid    string
	BoardingVOut    uint32
	RoundTxid       string
	RedeemTxid      string
	Amount          uint64
	Type            TxType
	IsPending       bool
	IsPendingChange bool
	CreatedAt       time.Time
}

func (t Transaction) Key() string {
	return fmt.Sprintf("%s:%s:%s", t.BoardingTxid, t.RoundTxid, t.RedeemTxid)
}

func (t Transaction) IsRound() bool {
	return t.RoundTxid != ""
}

func (t Transaction) IsBoarding() bool {
	return t.BoardingTxid != ""
}

func (t Transaction) IsRedeem() bool {
	return t.RedeemTxid != ""
}

const (
	BoardingPending    EventType = "boarding_pending"
	BoardingClaimed    EventType = "boarding_claimed"
	ArkSent            EventType = "ark_sent"
	ArkReceived        EventType = "ark_received"
	ArkSentPending     EventType = "ark_sent_pending"
	ArkSentClaimed     EventType = "ark_sent_claimed"
	ArkReceivedPending EventType = "ark_received_pending"
	ArkReceivedClaimed EventType = "ark_received_claimed"
)

type EventType string

type TransactionEvent struct {
	Tx    Transaction
	Event EventType
}
