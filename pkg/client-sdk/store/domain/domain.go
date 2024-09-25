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
	return v.Txid + ":" + strconv.Itoa(int(v.VOut))
}

const (
	TxSent     TxType = "sent"
	TxReceived TxType = "received"
)

type TxType string

type Transaction struct {
	BoardingTxid    string
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

func (t Transaction) IsBoarding() bool {
	return t.BoardingTxid != ""
}
