package btcwallet

import (
	"encoding/hex"

	"github.com/btcsuite/btcwallet/wallet"
)

// transactionOutputTxInput is a wrapper around wallet.TransactionOutput implementing the ports.TxInput interface
type transactionOutputTxInput struct {
	*wallet.TransactionOutput
}

func (t transactionOutputTxInput) GetIndex() uint32 {
	return t.OutPoint.Index
}

func (t transactionOutputTxInput) GetScript() string {
	return hex.EncodeToString(t.Output.PkScript)
}

func (t transactionOutputTxInput) GetTxid() string {
	return t.OutPoint.Hash.String()
}

func (t transactionOutputTxInput) GetValue() uint64 {
	return uint64(t.Output.Value)
}

// coinTxInput is a wrapper around wallet.Coin implementing the ports.TxInput interface
type coinTxInput struct {
	wallet.Coin
}

func (c coinTxInput) GetIndex() uint32 {
	return c.Index
}

func (c coinTxInput) GetScript() string {
	return hex.EncodeToString(c.PkScript)
}

func (c coinTxInput) GetTxid() string {
	return c.Hash.String()
}

func (c coinTxInput) GetValue() uint64 {
	return uint64(c.Value)
}
