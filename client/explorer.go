package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/vulpemventures/go-elements/transaction"
)

type Explorer interface {
	GetTxHex(txid string) (string, error)
	Broadcast(txHex string) (string, error)
}

type explorer struct {
	cache   map[string]string
	baseUrl string
}

func NewExplorer() Explorer {
	_, net := getNetwork()
	baseUrl := explorerUrl[net.Name]

	return &explorer{
		cache:   make(map[string]string),
		baseUrl: baseUrl,
	}
}

func (e *explorer) GetTxHex(txid string) (string, error) {
	if hex, ok := e.cache[txid]; ok {
		return hex, nil
	}

	txHex, err := e.getTxHex(txid)
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

		return "", err
	}

	return txid, nil
}

func (e *explorer) getTxHex(txid string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s/hex", e.baseUrl, txid))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf(string(body))
	}

	hex := string(body)
	e.cache[txid] = hex
	return hex, nil
}
