//go:build js && wasm
// +build js,wasm

package browser

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
	AspUrl                     string `json:"asp_url"`
	AspPubkey                  string `json:"asp_pubkey"`
	WalletType                 string `json:"wallet_type"`
	ClientType                 string `json:"client_type"`
	ExplorerURL                string `json:"explorer_url"`
	Network                    string `json:"network"`
	RoundLifetime              string `json:"round_lifetime"`
	RoundInterval              string `json:"round_interval"`
	UnilateralExitDelay        string `json:"unilateral_exit_delay"`
	Dust                       string `json:"dust"`
	ForfeitAddress             string `json:"forfeit_address"`
	BoardingDescriptorTemplate string `json:"boarding_descriptor_template"`
}

type localStorageStore struct {
	store js.Value
}

func NewLocalStorageStore() (db.ConfigStore, error) {
	store := js.Global().Get("localStorage")
	return &localStorageStore{store}, nil
}

func (s *localStorageStore) GetType() string {
	return LocalStorageStore
}

func (s *localStorageStore) GetDatadir() string {
	return ""
}

func (s *localStorageStore) AddData(ctx context.Context, data db.ConfigData) error {
	sd := &storeData{
		AspUrl:                     data.AspUrl,
		AspPubkey:                  hex.EncodeToString(data.AspPubkey.SerializeCompressed()),
		WalletType:                 data.WalletType,
		ClientType:                 data.ClientType,
		Network:                    data.Network.Name,
		RoundLifetime:              fmt.Sprintf("%d", data.RoundLifetime),
		RoundInterval:              fmt.Sprintf("%d", data.RoundInterval),
		UnilateralExitDelay:        fmt.Sprintf("%d", data.UnilateralExitDelay),
		Dust:                       fmt.Sprintf("%d", data.Dust),
		ExplorerURL:                data.ExplorerURL,
		ForfeitAddress:             data.ForfeitAddress,
		BoardingDescriptorTemplate: data.BoardingDescriptorTemplate,
	}
	return s.writeData(sd)
}

func (s *localStorageStore) GetData(ctx context.Context) (*db.ConfigData, error) {
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
	roundInterval, _ := strconv.Atoi(s.store.Call("getItem", "round_interval").String())
	unilateralExitDelay, _ := strconv.Atoi(s.store.Call("getItem", "unilateral_exit_delay").String())
	dust, _ := strconv.Atoi(s.store.Call("getItem", "min_relay_fee").String())

<<<<<<< HEAD
	return &db.ConfigData{
		AspUrl:              s.store.Call("getItem", "asp_url").String(),
		AspPubkey:           aspPubkey,
		WalletType:          s.store.Call("getItem", "wallet_type").String(),
		ClientType:          s.store.Call("getItem", "client_type").String(),
		Network:             network,
		RoundLifetime:       int64(roundLifetime),
		RoundInterval:       int64(roundInterval),
		UnilateralExitDelay: int64(unilateralExitDelay),
		Dust:                uint64(dust),
=======
	return &store.StoreData{
		AspUrl:                     s.store.Call("getItem", "asp_url").String(),
		AspPubkey:                  aspPubkey,
		WalletType:                 s.store.Call("getItem", "wallet_type").String(),
		ClientType:                 s.store.Call("getItem", "client_type").String(),
		Network:                    network,
		RoundLifetime:              int64(roundLifetime),
		RoundInterval:              int64(roundInterval),
		UnilateralExitDelay:        int64(unilateralExitDelay),
		Dust:                       uint64(dust),
		ExplorerURL:                s.store.Call("getItem", "explorer_url").String(),
		ForfeitAddress:             s.store.Call("getItem", "forfeit_address").String(),
		BoardingDescriptorTemplate: s.store.Call("getItem", "boarding_descriptor_template").String(),
>>>>>>> master
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
