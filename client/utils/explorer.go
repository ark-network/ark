package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

type Utxo struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Amount uint64 `json:"value"`
	Asset  string `json:"asset,omitempty"` // optional
	Status struct {
		Confirmed bool  `json:"confirmed"`
		Blocktime int64 `json:"block_time"`
	} `json:"status"`
}

type Explorer interface {
	GetTxHex(txid string) (string, error)
	Broadcast(txHex string) (string, error)
	GetUtxos(addr string) ([]Utxo, error)
	GetBalance(addr, asset string) (uint64, error)
	GetRedeemedVtxosBalance(
		addr string, unilateralExitDelay int64,
	) (uint64, map[int64]uint64, error)
	GetTxBlocktime(txid string) (confirmed bool, blocktime int64, err error)
	GetFeeRate() (float64, error)
}

type explorer struct {
	cache   map[string]string
	baseUrl string
}

func NewExplorer(ctx *cli.Context) Explorer {
	baseUrl, err := getBaseURL(ctx)
	if err != nil {
		panic(err)
	}

	return &explorer{
		cache:   make(map[string]string),
		baseUrl: baseUrl,
	}
}

func (e *explorer) GetFeeRate() (float64, error) {
	endpoint, err := url.JoinPath(e.baseUrl, "fee-estimates")
	if err != nil {
		return 0, err
	}

	resp, err := http.Get(endpoint)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var response map[string]float64

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("error getting fee rate: %s", resp.Status)
	}

	if len(response) == 0 {
		fmt.Println("empty fee-estimates response, default to 2 sat/vbyte")
		return 2, nil
	}

	return response["1"], nil
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

func (e *explorer) Broadcast(txStr string) (string, error) {
	tx, err := transaction.NewTxFromHex(txStr)
	if err != nil {
		pset, err := psetv2.NewPsetFromBase64(txStr)
		if err != nil {
			return "", err
		}

		tx, err = psetv2.Extract(pset)
		if err != nil {
			return "", err
		}
		txStr, _ = tx.ToHex()
	}
	txid := tx.TxHash().String()
	e.cache[txid] = txStr

	txid, err = e.broadcast(txStr)
	if err != nil {
		if strings.Contains(
			strings.ToLower(err.Error()), "transaction already in block chain",
		) {
			return txid, nil
		}

		return "", err
	}

	return txid, nil
}

func (e *explorer) GetUtxos(addr string) ([]Utxo, error) {
	endpoint, err := url.JoinPath(e.baseUrl, "address", addr, "utxo")
	if err != nil {
		return nil, err
	}

	resp, err := http.Get(endpoint)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(string(body))
	}
	payload := []Utxo{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func (e *explorer) GetBalance(addr, asset string) (uint64, error) {
	payload, err := e.GetUtxos(addr)
	if err != nil {
		return 0, err
	}

	balance := uint64(0)
	for _, p := range payload {
		if len(asset) > 0 {
			if p.Asset != asset {
				continue
			}
		}
		balance += p.Amount
	}
	return balance, nil
}

func (e *explorer) GetRedeemedVtxosBalance(
	addr string, unilateralExitDelay int64,
) (spendableBalance uint64, lockedBalance map[int64]uint64, err error) {
	utxos, err := e.GetUtxos(addr)
	if err != nil {
		return
	}

	lockedBalance = make(map[int64]uint64, 0)
	now := time.Now()
	for _, utxo := range utxos {
		blocktime := now
		if utxo.Status.Confirmed {
			blocktime = time.Unix(utxo.Status.Blocktime, 0)
		}

		delay := time.Duration(unilateralExitDelay) * time.Second
		availableAt := blocktime.Add(delay)
		if availableAt.After(now) {
			if _, ok := lockedBalance[availableAt.Unix()]; !ok {
				lockedBalance[availableAt.Unix()] = 0
			}

			lockedBalance[availableAt.Unix()] += utxo.Amount
		} else {
			spendableBalance += utxo.Amount
		}
	}

	return
}

func (e *explorer) GetTxBlocktime(txid string) (confirmed bool, blocktime int64, err error) {
	endpoint, err := url.JoinPath(e.baseUrl, "tx", txid)
	if err != nil {
		return false, 0, err
	}

	resp, err := http.Get(endpoint)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf(string(body))
	}

	var tx struct {
		Status struct {
			Confirmed bool  `json:"confirmed"`
			Blocktime int64 `json:"block_time"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &tx); err != nil {
		return false, 0, err
	}

	if !tx.Status.Confirmed {
		return false, -1, nil
	}

	return true, tx.Status.Blocktime, nil

}

func (e *explorer) getTxHex(txid string) (string, error) {
	endpoint, err := url.JoinPath(e.baseUrl, "tx", txid, "hex")
	if err != nil {
		return "", err
	}

	resp, err := http.Get(endpoint)
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

func (e *explorer) broadcast(txHex string) (string, error) {
	body := bytes.NewBuffer([]byte(txHex))

	endpoint, err := url.JoinPath(e.baseUrl, "tx")
	if err != nil {
		return "", err
	}

	resp, err := http.Post(endpoint, "text/plain", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bodyResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf(string(bodyResponse))
	}

	return string(bodyResponse), nil
}
