package btcwallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/wire"
)

type esploraClient struct {
	url string
}

type esploraTx struct {
	Status struct {
		Confirmed   bool  `json:"confirmed"`
		BlockTime   int64 `json:"block_time"`
		BlockNumber int64 `json:"block_height"`
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

func (f *esploraClient) getTx(txid string) (*wire.MsgTx, error) {
	endpoint, err := url.JoinPath(f.url, "tx", txid, "raw")
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("tx endpoint HTTP error: " + resp.Status)
	}

	var tx wire.MsgTx

	if err := tx.Deserialize(resp.Body); err != nil {
		return nil, err
	}

	return &tx, nil
}

func (f *esploraClient) getTxStatus(txid string) (isConfirmed bool, blocknumber, blocktime int64, err error) {
	endpoint, err := url.JoinPath(f.url, "tx", txid)
	if err != nil {
		return false, 0, 0, err
	}

	resp, err := http.DefaultClient.Get(endpoint)
	if err != nil {
		return false, 0, 0, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, 0, err
	}

	var response esploraTx

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return false, 0, 0, err
	}

	return response.Status.Confirmed, response.Status.BlockNumber, response.Status.BlockTime, nil
}

// GetFeeMap returns a map of sat/vbyte fees for different confirmation targets
// it implements the chainfee.WebAPIFeeSource interface
func (f *esploraClient) GetFeeMap() (map[uint32]uint32, error) {
	endpoint, err := url.JoinPath(f.url, "fee-estimates")
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("fee-estimates endpoint HTTP error: " + resp.Status)
	}

	response := make(map[string]float64)

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	if len(response) == 0 {
		response = map[string]float64{"1": 2.0}
	}

	mapResponse := make(map[uint32]uint32)
	for k, v := range response {
		key, err := strconv.Atoi(k)
		if err != nil {
			return nil, err
		}

		mapResponse[uint32(key)] = uint32(v * 1000)
	}

	return mapResponse, nil
}
