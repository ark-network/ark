package types

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	InMemoryStore = "inmemory"
	FileStore     = "file"
	KVStore       = "kv"
)

type Config struct {
	ServerUrl                  string
	ServerPubKey               *secp256k1.PublicKey
	WalletType                 string
	ClientType                 string
	Network                    common.Network
	VtxoTreeExpiry             common.RelativeLocktime
	RoundInterval              int64
	UnilateralExitDelay        common.RelativeLocktime
	Dust                       uint64
	BoardingDescriptorTemplate string
	ExplorerURL                string
	ForfeitAddress             string
	WithTransactionFeed        bool
}

type VtxoKey struct {
	Txid string
	VOut uint32
}

func (v VtxoKey) String() string {
	return fmt.Sprintf("%s:%s", v.Txid, strconv.Itoa(int(v.VOut)))
}

type Vtxo struct {
	VtxoKey
	Amount                  uint64
	RoundTxid               string
	ExpiresAt               time.Time
	CreatedAt               time.Time
	RedeemTx                string
	UnconditionalForfeitTxs []string
	Pending                 bool
	SpentBy                 string
	Spent                   bool
}

const (
	TxSent     TxType = "SENT"
	TxReceived TxType = "RECEIVED"
)

type TxType string

type TransactionKey struct {
	BoardingTxid string
	RoundTxid    string
	RedeemTxid   string
}

func (t TransactionKey) String() string {
	return fmt.Sprintf("%s%s%s", t.BoardingTxid, t.RoundTxid, t.RedeemTxid)
}

type Transaction struct {
	TransactionKey
	Amount    uint64
	Type      TxType
	Settled   bool
	CreatedAt time.Time
	SpentBy   string
}

func (t Transaction) IsRound() bool {
	return t.RoundTxid != ""
}

func (t Transaction) IsBoarding() bool {
	return t.BoardingTxid != ""
}

func (t Transaction) IsOOR() bool {
	return t.RedeemTxid != ""
}

func (t Transaction) String() string {
	buf, _ := json.MarshalIndent(t, "", "  ")
	return string(buf)
}

const (
	BoardingPending EventType = "BOARDING_PENDING"
	BoardingSettled EventType = "BOARDING_SETTLED"
	OORSent         EventType = "OOR_SENT"
	OORReceived     EventType = "OOR_RECEIVED"
	OORSettled      EventType = "OOR_SETTLED"
)

type EventType string

type TransactionEvent struct {
	Tx    Transaction
	Event EventType
}

type Utxo struct {
	Txid        string
	VOut        uint32
	Amount      uint64
	Asset       string // liquid only
	Delay       common.RelativeLocktime
	SpendableAt time.Time
	CreatedAt   time.Time
	Tapscripts  []string
	Spent       bool
}

func (u *Utxo) Sequence() (uint32, error) {
	return common.BIP68Sequence(u.Delay)
}
