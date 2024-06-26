package btcwallet

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/wallet/txrules"
)

var errFeeEstimator = errors.New("failed to get fee rate")

type feeEstimator struct {
	esploraURL string
}

func newFeeEstimator(netParams *chaincfg.Params) *feeEstimator {
	var url string

	switch netParams.Name {
	case "mainnet":
		url = "https://blockstream.info/api/"
	case "testnet3":
		url = "https://blockstream.info/testnet/api/"
	case "regtest":
		url = ""
	}

	return &feeEstimator{
		url,
	}
}

func (f *feeEstimator) getFeeRate() (btcutil.Amount, error) {
	if len(f.esploraURL) == 0 {
		return txrules.DefaultRelayFeePerKb, nil
	}

	resp, err := http.DefaultClient.Get(f.esploraURL + "fee-estimates")
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
