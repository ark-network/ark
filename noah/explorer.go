package main

import (
	"strings"
	"time"

	"github.com/vulpemventures/go-elements/transaction"
)

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

	txid, err = broadcast(txHex)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "transaction already in block chain") {
			return txid, nil
		}

		if strings.Contains(strings.ToLower(err.Error()), "bad-txns-inputs-missingorspent") {
			time.Sleep(5 * time.Second)
			return e.Broadcast(txHex)
		}

		return "", err
	}

	return txid, nil
}
