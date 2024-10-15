package explorer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

const (
	BitcoinExplorer = "bitcoin"
	LiquidExplorer  = "liquid"
)

type Utxo struct {
	Txid        string
	Vout        uint32
	Amount      uint64
	Asset       string // liquid only
	Delay       uint
	SpendableAt time.Time
	CreatedAt   time.Time
}

func (u *Utxo) Sequence() (uint32, error) {
	return common.BIP68Sequence(u.Delay)
}

func newUtxo(explorerUtxo ExplorerUtxo, delay uint) Utxo {
	utxoTime := explorerUtxo.Status.Blocktime
	createdAt := time.Unix(utxoTime, 0)
	if utxoTime == 0 {
		createdAt = time.Time{}
		utxoTime = time.Now().Unix()
	}

	return Utxo{
		Txid:        explorerUtxo.Txid,
		Vout:        explorerUtxo.Vout,
		Amount:      explorerUtxo.Amount,
		Asset:       explorerUtxo.Asset,
		Delay:       delay,
		SpendableAt: time.Unix(utxoTime, 0).Add(time.Duration(delay) * time.Second),
		CreatedAt:   createdAt,
	}
}

type ExplorerTx struct {
	Txid string `json:"txid"`
	Vout []struct {
		Address string `json:"scriptpubkey_address"`
		Amount  uint64 `json:"value"`
	} `json:"vout"`
	Status struct {
		Confirmed bool  `json:"confirmed"`
		Blocktime int64 `json:"block_time"`
	} `json:"status"`
}

type ExplorerUtxo struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Amount uint64 `json:"value"`
	Asset  string `json:"asset,omitempty"`
	Status struct {
		Confirmed bool  `json:"confirmed"`
		Blocktime int64 `json:"block_time"`
	} `json:"status"`
}

type SpentStatus struct {
	Spent   bool   `json:"spent"`
	SpentBy string `json:"txid,omitempty"`
}

func (e ExplorerUtxo) ToUtxo(delay uint) Utxo {
	return newUtxo(e, delay)
}

type Explorer interface {
	GetTxHex(txid string) (string, error)
	Broadcast(txHex string) (string, error)
	GetTxs(addr string) ([]ExplorerTx, error)
	GetTxOutspends(tx string) ([]SpentStatus, error)
	GetUtxos(addr string) ([]ExplorerUtxo, error)
	GetBalance(addr string) (uint64, error)
	GetRedeemedVtxosBalance(
		addr string, unilateralExitDelay int64,
	) (uint64, map[int64]uint64, error)
	GetTxBlockTime(
		txid string,
	) (confirmed bool, blocktime int64, err error)
	// GetNetwork() common.Network
	BaseUrl() string
	GetFeeRate() (float64, error)
}

type explorerSvc struct {
	cache   *utils.Cache[string]
	baseUrl string
	net     common.Network
}

func NewExplorer(baseUrl string, net common.Network) Explorer {
	return &explorerSvc{
		cache:   utils.NewCache[string](),
		baseUrl: baseUrl,
		net:     net,
	}
}

func (e *explorerSvc) BaseUrl() string {
	return e.baseUrl
}

func (e *explorerSvc) GetNetwork() common.Network {
	return e.net
}

func (e *explorerSvc) GetFeeRate() (float64, error) {
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
		return 1, nil
	}

	return response["1"], nil
}

func (e *explorerSvc) GetTxHex(txid string) (string, error) {
	if hex, ok := e.cache.Get(txid); ok {
		return hex, nil
	}

	txHex, err := e.getTxHex(txid)
	if err != nil {
		return "", err
	}

	e.cache.Set(txid, txHex)

	return txHex, nil
}

func (e *explorerSvc) Broadcast(txStr string) (string, error) {
	clone := strings.Clone(txStr)
	txStr, txid, err := parseLiquidTx(txStr)
	if err != nil {
		txStr, txid, err = parseBitcoinTx(clone)
		if err != nil {
			return "", err
		}
	}

	e.cache.Set(txid, txStr)

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

func (e *explorerSvc) GetTxs(addr string) ([]ExplorerTx, error) {
	resp, err := http.Get(fmt.Sprintf("%s/address/%s/txs", e.baseUrl, addr))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get txs: %s", string(body))
	}
	payload := []ExplorerTx{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func (e *explorerSvc) GetTxOutspends(txid string) ([]SpentStatus, error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s/outspends", e.baseUrl, txid))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get txs: %s", string(body))
	}

	spentStatuses := make([]SpentStatus, 0)
	if err := json.Unmarshal(body, &spentStatuses); err != nil {
		return nil, err
	}
	return spentStatuses, nil
}

func (e *explorerSvc) GetUtxos(addr string) ([]ExplorerUtxo, error) {
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
		return nil, fmt.Errorf("failed to get utxos: %s", string(body))
	}
	payload := []ExplorerUtxo{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func (e *explorerSvc) GetBalance(addr string) (uint64, error) {
	payload, err := e.GetUtxos(addr)
	if err != nil {
		return 0, err
	}

	balance := uint64(0)
	for _, p := range payload {
		balance += p.Amount
	}
	return balance, nil
}

func (e *explorerSvc) GetRedeemedVtxosBalance(
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

func (e *explorerSvc) GetTxBlockTime(
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
		return false, 0, fmt.Errorf("failed to get block time: %s", string(body))
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

func (e *explorerSvc) getTxHex(txid string) (string, error) {
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
		return "", fmt.Errorf("failed to get tx hex: %s", string(body))
	}

	hex := string(body)
	e.cache.Set(txid, hex)
	return hex, nil
}

func (e *explorerSvc) broadcast(txHex string) (string, error) {
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
		return "", fmt.Errorf("failed to broadcast: %s", string(bodyResponse))
	}

	return string(bodyResponse), nil
}

func parseLiquidTx(txStr string) (string, string, error) {
	tx, err := transaction.NewTxFromHex(txStr)
	if err != nil {
		pset, err := psetv2.NewPsetFromBase64(txStr)
		if err != nil {
			return "", "", err
		}

		tx, err = psetv2.Extract(pset)
		if err != nil {
			return "", "", err
		}

		txhex, err := tx.ToHex()
		if err != nil {
			return "", "", err
		}

		txid := tx.TxHash().String()

		return txhex, txid, nil
	}

	txhex, err := tx.ToHex()
	if err != nil {
		return "", "", err
	}

	txid := tx.TxHash().String()

	return txhex, txid, nil
}

func parseBitcoinTx(txStr string) (string, string, error) {
	var tx wire.MsgTx

	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txStr))); err != nil {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(txStr), true)
		if err != nil {
			return "", "", err
		}

		txFromPartial, err := psbt.Extract(ptx)
		if err != nil {
			return "", "", err
		}

		tx = *txFromPartial
	}

	var txBuf bytes.Buffer

	if err := tx.Serialize(&txBuf); err != nil {
		return "", "", err
	}

	txhex := hex.EncodeToString(txBuf.Bytes())
	txid := tx.TxHash().String()

	return txhex, txid, nil
}
