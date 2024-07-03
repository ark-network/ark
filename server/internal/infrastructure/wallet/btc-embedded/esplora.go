package btcwallet

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcutil"
)

var errFeeEstimator = errors.New("failed to get fee rate")

type esploraClient struct {
	url string
}

func newEsploraClient(network common.Network) *esploraClient {
	var url string

	switch network.Name {
	case common.Bitcoin.Name:
		url = "https://blockstream.info/api/"
	case common.BitcoinTestNet.Name:
		url = "https://blockstream.info/testnet/api/"
	case common.BitcoinRegTest.Name:
		url = "http://localhost:3000/" // nigiri chopsticks
	}

	return &esploraClient{
		url,
	}
}

func (f *esploraClient) getTxStatus(txid string) (isConfirmed bool, blocktime int64, err error) {
	resp, err := http.DefaultClient.Get(f.url + "tx/" + txid)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, err
	}

	var response esploraTx

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return false, 0, err
	}

	return response.Status.Confirmed, response.Status.BlockTime, nil
}

func (f *esploraClient) getFeeRate() (btcutil.Amount, error) {
	resp, err := http.DefaultClient.Get(f.url + "fee-estimates")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, errFeeEstimator
	}

	response := make(map[string]float64)

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return 0, err
	}

	feeRate, ok := response["1"]
	if !ok {
		return 0, errFeeEstimator
	}

	return btcutil.Amount(feeRate * 1000), nil
}

type esploraTx struct {
	Status struct {
		Confirmed bool  `json:"confirmed"`
		BlockTime int64 `json:"block_time"`
	} `json:"status"`
}
