package store

import (
	"time"

	"github.com/ark-network/ark/common"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type StoreData struct {
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

const (
	TxSent     TxType = "sent"
	TxReceived TxType = "received"
)

type TxType string

type Transaction struct {
	ID              string
	BoardingTxid    string
	RoundTxid       string
	RedeemTxid      string
	Amount          uint64
	Type            TxType
	IsPending       bool
	IsPendingChange bool
	CreatedAt       time.Time
}
