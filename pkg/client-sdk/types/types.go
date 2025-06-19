package types

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	InMemoryStore = "inmemory"
	FileStore     = "file"
	KVStore       = "kv"
	SQLStore      = "sql"
)

type Config struct {
	ServerUrl               string
	ServerPubKey            *secp256k1.PublicKey
	WalletType              string
	ClientType              string
	Network                 common.Network
	VtxoTreeExpiry          common.RelativeLocktime
	RoundInterval           int64
	UnilateralExitDelay     common.RelativeLocktime
	Dust                    uint64
	BoardingExitDelay       common.RelativeLocktime
	ExplorerURL             string
	ForfeitAddress          string
	WithTransactionFeed     bool
	MarketHourStartTime     int64
	MarketHourEndTime       int64
	MarketHourPeriod        int64
	MarketHourRoundInterval int64
	UtxoMinAmount           int64
	UtxoMaxAmount           int64
	VtxoMinAmount           int64
	VtxoMaxAmount           int64
}

type VtxoKey struct {
	Txid string
	VOut uint32
}

func (v VtxoKey) String() string {
	return fmt.Sprintf("%s:%d", v.Txid, v.VOut)
}

type Vtxo struct {
	VtxoKey
	Script         string
	Amount         uint64
	CommitmentTxid string
	ExpiresAt      time.Time
	CreatedAt      time.Time
	Preconfirmed   bool
	Swept          bool
	Redeemed       bool
	Spent          bool
	SpentBy        string
}

func (v Vtxo) IsRecoverable() bool {
	return v.Swept && !v.Spent
}

func (v Vtxo) Address(server *secp256k1.PublicKey, net common.Network) (string, error) {
	pubkeyBytes, err := hex.DecodeString(v.Script)
	if err != nil {
		return "", err
	}

	pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return "", err
	}

	a := &common.Address{
		HRP:        net.Addr,
		Server:     server,
		VtxoTapKey: pubkey,
	}

	return a.Encode()
}

type VtxoEventType int

const (
	VtxosAdded VtxoEventType = iota
	VtxosSpent
	VtxosUpdated
)

func (e VtxoEventType) String() string {
	return map[VtxoEventType]string{
		VtxosAdded: "VTXOS_ADDED",
		VtxosSpent: "VTXOS_SPENT",
	}[e]
}

type VtxoEvent struct {
	Type  VtxoEventType
	Vtxos []Vtxo
}

const (
	TxSent     TxType = "SENT"
	TxReceived TxType = "RECEIVED"
)

type TxType string

type TransactionKey struct {
	BoardingTxid   string
	CommitmentTxid string
	ArkTxid        string
}

func (t TransactionKey) String() string {
	return fmt.Sprintf("%s%s%s", t.BoardingTxid, t.CommitmentTxid, t.ArkTxid)
}

type Transaction struct {
	TransactionKey
	Amount    uint64
	Type      TxType
	Settled   bool
	CreatedAt time.Time
	Hex       string
}

func (t Transaction) String() string {
	buf, _ := json.MarshalIndent(t, "", "  ")
	return string(buf)
}

type TxEventType int

const (
	TxsAdded TxEventType = iota
	TxsSettled
	TxsConfirmed
	TxsReplaced
	TxsUpdated
)

func (e TxEventType) String() string {
	return map[TxEventType]string{
		TxsAdded:     "TXS_ADDED",
		TxsSettled:   "TXS_SETTLED",
		TxsConfirmed: "TXS_CONFIRMED",
		TxsReplaced:  "TXS_REPLACED",
	}[e]
}

type TransactionEvent struct {
	Type         TxEventType
	Txs          []Transaction
	Replacements map[string]string
}

type Utxo struct {
	Txid        string
	VOut        uint32
	Amount      uint64
	Delay       common.RelativeLocktime
	SpendableAt time.Time
	CreatedAt   time.Time
	Tapscripts  []string
	Spent       bool
	Tx          string
}

func (u *Utxo) Sequence() (uint32, error) {
	return common.BIP68Sequence(u.Delay)
}
