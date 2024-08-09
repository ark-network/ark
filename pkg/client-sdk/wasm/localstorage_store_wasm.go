package arksdkwasm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"syscall/js"

	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	LocalStorageStore = "localstorage"
)

type storeData struct {
	AspUrl              string `json:"asp_url"`
	AspPubkey           string `json:"asp_pubkey"`
	WalletType          string `json:"wallet_type"`
	ClientType          string `json:"client_type"`
	ExplorerURL         string `json:"explorer_url"`
	Network             string `json:"network"`
	RoundLifetime       string `json:"round_lifetime"`
	UnilateralExitDelay string `json:"unilateral_exit_delay"`
	MinRelayFee         string `json:"min_relay_fee"`
}

type localStorageStore struct {
	store js.Value
}

func NewLocalStorageStore() (store.ConfigStore, error) {
	store := js.Global().Get("localStorage")
	return &localStorageStore{store}, nil
}

func (s *localStorageStore) GetType() string {
	return LocalStorageStore
}

func (s *localStorageStore) GetDatadir() string {
	return ""
}

func (s *localStorageStore) AddData(ctx context.Context, data store.StoreData) error {
	sd := &storeData{
		AspUrl:              data.AspUrl,
		AspPubkey:           hex.EncodeToString(data.AspPubkey.SerializeCompressed()),
		WalletType:          data.WalletType,
		ClientType:          data.ClientType,
		Network:             data.Network.Name,
		RoundLifetime:       fmt.Sprintf("%d", data.RoundLifetime),
		UnilateralExitDelay: fmt.Sprintf("%d", data.UnilateralExitDelay),
		MinRelayFee:         fmt.Sprintf("%d", data.MinRelayFee),
	}
	return s.writeData(sd)
}

func (s *localStorageStore) GetData(ctx context.Context) (*store.StoreData, error) {
	key := s.store.Call("getItem", "asp_pubkey")
	if key.IsNull() || key.IsUndefined() {
		return nil, nil
	}
	buf, err := hex.DecodeString(key.String())
	if err != nil {
		return nil, err
	}
	if len(buf) <= 0 {
		return nil, nil
	}

	aspPubkey, err := secp256k1.ParsePubKey(buf)
	if err != nil {
		return nil, err
	}
	network := utils.NetworkFromString(s.store.Call("getItem", "network").String())
	roundLifetime, _ := strconv.Atoi(s.store.Call("getItem", "round_lifetime").String())
	unilateralExitDelay, _ := strconv.Atoi(s.store.Call("getItem", "unilateral_exit_delay").String())
	minRelayFee, _ := strconv.Atoi(s.store.Call("getItem", "min_relay_fee").String())

	return &store.StoreData{
		AspUrl:              s.store.Call("getItem", "asp_url").String(),
		AspPubkey:           aspPubkey,
		WalletType:          s.store.Call("getItem", "wallet_type").String(),
		ClientType:          s.store.Call("getItem", "client_type").String(),
		Network:             network,
		RoundLifetime:       int64(roundLifetime),
		UnilateralExitDelay: int64(unilateralExitDelay),
		MinRelayFee:         uint64(minRelayFee),
	}, nil
}

func (s *localStorageStore) CleanData(ctx context.Context) error {
	if err := s.writeData(&storeData{}); err != nil {
		return fmt.Errorf("failed to write to store: %s", err)
	}
	return nil
}

func (s *localStorageStore) writeData(data *storeData) error {
	dataMap := make(map[string]string)
	buf, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(buf, &dataMap); err != nil {
		return err
	}
	for key, value := range dataMap {
		s.store.Call("setItem", key, value)
	}
	return nil
}
