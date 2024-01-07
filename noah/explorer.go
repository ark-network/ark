package main

import "github.com/vulpemventures/go-elements/transaction"

type Explorer interface {
	GetTxHex(txid string) (string, error)
	Broadcast(txHex string) (string, error)
}

type explorer struct {
	cache map[string]string
}

func NewExplorer() Explorer {
	return &explorer{
		cache: make(map[string]string),
	}
}

func (e *explorer) GetTxHex(txid string) (string, error) {
	if hex, ok := e.cache[txid]; ok {
		return hex, nil
	}

	txHex, err := getTxHex(txid)
	if err != nil {
		return "", err
	}

	e.cache[txid] = txHex

	return txHex, nil
}

func (e *explorer) Broadcast(txHex string) (string, error) {
	tx, err := transaction.NewTxFromHex(txHex)
	if err != nil {
		return "", err
	}
	txid := tx.TxHash().String()
	e.cache[txid] = txHex

	return broadcast(txHex)
}
