package liquidexplorer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ark-network/ark-sdk/explorer"
	"github.com/ark-network/ark/common"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

type liquidExplorer struct {
	cache   map[string]string
	baseUrl string
	net     string
}

func NewExplorer(baseUrl string, net string) explorer.Explorer {
	return &liquidExplorer{
		cache:   make(map[string]string),
		baseUrl: baseUrl,
		net:     net,
	}
}

func (e *liquidExplorer) BaseUrl() string {
	return e.baseUrl
}

func (e *liquidExplorer) GetNetwork() network.Network {
	return e.liquidNetwork()
}

func (e *liquidExplorer) GetTxHex(txid string) (string, error) {
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

func (e *liquidExplorer) Broadcast(txStr string) (string, error) {
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

func (e *liquidExplorer) GetUtxos(addr string) ([]explorer.Utxo, error) {
	resp, err := http.Get(fmt.Sprintf("%s/address/%s/utxo", e.baseUrl, addr))
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
	payload := []explorer.Utxo{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func (e *liquidExplorer) GetBalance(addr string) (uint64, error) {
	payload, err := e.GetUtxos(addr)
	if err != nil {
		return 0, err
	}
	asset := e.liquidNetwork().AssetID

	balance := uint64(0)
	for _, p := range payload {
		if p.Asset != asset {
			continue
		}
		balance += p.Amount
	}
	return balance, nil
}

func (e *liquidExplorer) GetRedeemedVtxosBalance(
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

func (e *liquidExplorer) GetTxBlockTime(
	txid string,
) (confirmed bool, blocktime int64, err error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s", e.baseUrl, txid))
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

func (e *liquidExplorer) getTxHex(txid string) (string, error) {
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

func (e *liquidExplorer) broadcast(txHex string) (string, error) {
	body := bytes.NewBuffer([]byte(txHex))

	resp, err := http.Post(fmt.Sprintf("%s/tx", e.baseUrl), "text/plain", body)
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

func (e *liquidExplorer) liquidNetwork() network.Network {
	if e.net == common.LiquidTestNet.Name {
		return network.Testnet
	}
	if e.net == common.LiquidRegTest.Name {
		return network.Regtest
	}
	return network.Liquid
}
