package utils

import (
	"time"

	"github.com/ark-network/ark/common"
)

type Utxo struct {
	Txid        string
	Vout        uint32
	Amount      uint64
	Asset       string // optional
	Delay       uint
	SpendableAt time.Time
}

func (u *Utxo) Sequence() (uint32, error) {
	return common.BIP68EncodeAsNumber(u.Delay)
}

func NewUtxo(explorerUtxo ExplorerUtxo, delay uint) Utxo {
	utxoTime := explorerUtxo.Status.Blocktime
	if utxoTime == 0 {
		utxoTime = time.Now().Unix()
	}

	return Utxo{
		Txid:        explorerUtxo.Txid,
		Vout:        explorerUtxo.Vout,
		Amount:      explorerUtxo.Amount,
		Asset:       explorerUtxo.Asset,
		Delay:       delay,
		SpendableAt: time.Unix(utxoTime, 0).Add(time.Duration(delay) * time.Second),
	}
}
