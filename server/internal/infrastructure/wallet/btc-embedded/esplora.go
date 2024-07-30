package btcwallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil"
	log "github.com/sirupsen/logrus"
)

type esploraClient struct {
	url string
}

type esploraTx struct {
	Status struct {
		Confirmed bool  `json:"confirmed"`
		BlockTime int64 `json:"block_time"`
	} `json:"status"`
}

func (f *esploraClient) broadcast(txhex string) error {
	endpoint, err := url.JoinPath(f.url, "tx")
	if err != nil {
		return err
	}

	resp, err := http.Post(endpoint, "text/plain", strings.NewReader(txhex))
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		content, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if strings.Contains(strings.ToLower(string(content)), "non-BIP68-final") {
			return ports.ErrNonFinalBIP68
		}

		return fmt.Errorf("failed to broadcast transaction: %s (%s, %s)", txhex, resp.Status, content)
	}

	return nil
}

func (f *esploraClient) getTxStatus(txid string) (isConfirmed bool, blocktime int64, err error) {
	endpoint, err := url.JoinPath(f.url, "tx", txid)
	if err != nil {
		return false, 0, err
	}

	resp, err := http.DefaultClient.Get(endpoint)
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
	endpoint, err := url.JoinPath(f.url, "fee-estimates")
	if err != nil {
		return 0, err
	}

	resp, err := http.DefaultClient.Get(endpoint)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, errors.New("fee-estimates endpoint HTTP error: " + resp.Status)
	}

	response := make(map[string]float64)

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return 0, err
	}

	if len(response) == 0 {
		log.Warn("empty response from esplora fee-estimates endpoint, default to 2 sat/vbyte")
		return 2.0, nil
	}

	feeRate, ok := response["1"]
	if !ok {
		return 0, errors.New("failed to get fee rate for 1 block")
	}

	return btcutil.Amount(feeRate * 1000), nil
}
