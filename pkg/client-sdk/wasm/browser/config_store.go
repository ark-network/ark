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

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	LocalStorageStore = "localstorage"
)

type storeData struct {
	ServerUrl                  string `json:"server_url"`
	ServerPubKey               string `json:"server_pubkey"`
	WalletType                 string `json:"wallet_type"`
	ClientType                 string `json:"client_type"`
	ExplorerURL                string `json:"explorer_url"`
	Network                    string `json:"network"`
	VtxoTreeExpiry             string `json:"vtxo_tree_expiry"`
	RoundInterval              string `json:"round_interval"`
	UnilateralExitDelay        string `json:"unilateral_exit_delay"`
	Dust                       string `json:"dust"`
	ForfeitAddress             string `json:"forfeit_address"`
	BoardingDescriptorTemplate string `json:"boarding_descriptor_template"`
	WithTransactionFeed        string `json:"with_transaction_feed"`
}

type configStore struct {
	store js.Value
}

func NewConfigStore(store js.Value) types.ConfigStore {
	return &configStore{store}
}

func (s *configStore) GetType() string {
	return LocalStorageStore
}

func (s *configStore) GetDatadir() string {
	return ""
}

func (s *configStore) AddData(ctx context.Context, data types.Config) error {
	sd := &storeData{
		ServerUrl:                  data.ServerUrl,
		ServerPubKey:               hex.EncodeToString(data.ServerPubKey.SerializeCompressed()),
		WalletType:                 data.WalletType,
		ClientType:                 data.ClientType,
		Network:                    data.Network.Name,
		VtxoTreeExpiry:             fmt.Sprintf("%d", data.VtxoTreeExpiry.Value),
		RoundInterval:              fmt.Sprintf("%d", data.RoundInterval),
		UnilateralExitDelay:        fmt.Sprintf("%d", data.UnilateralExitDelay.Value),
		Dust:                       fmt.Sprintf("%d", data.Dust),
		ExplorerURL:                data.ExplorerURL,
		ForfeitAddress:             data.ForfeitAddress,
		BoardingDescriptorTemplate: data.BoardingDescriptorTemplate,
	}
	return s.writeData(sd)
}

func (s *configStore) GetData(ctx context.Context) (*types.Config, error) {
	key := s.store.Call("getItem", "server_pubkey")
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

	serverPubkey, err := secp256k1.ParsePubKey(buf)
	if err != nil {
		return nil, err
	}
	network := utils.NetworkFromString(s.store.Call("getItem", "network").String())
	vtxoTreeExpiry, _ := strconv.Atoi(s.store.Call("getItem", "vtxo_tree_expiry").String())
	roundInterval, _ := strconv.Atoi(s.store.Call("getItem", "round_interval").String())
	unilateralExitDelay, _ := strconv.Atoi(s.store.Call("getItem", "unilateral_exit_delay").String())
	dust, _ := strconv.Atoi(s.store.Call("getItem", "dust").String())
	withTxFeed, _ := strconv.ParseBool(s.store.Call("getItem", "with_transaction_feed").String())

	vtxoTreeExpiryType := common.LocktimeTypeBlock
	if vtxoTreeExpiry >= 512 {
		vtxoTreeExpiryType = common.LocktimeTypeSecond
	}

	unilateralExitDelayType := common.LocktimeTypeBlock
	if unilateralExitDelay >= 512 {
		unilateralExitDelayType = common.LocktimeTypeSecond
	}

	return &types.Config{
		ServerUrl:                  s.store.Call("getItem", "server_url").String(),
		ServerPubKey:               serverPubkey,
		WalletType:                 s.store.Call("getItem", "wallet_type").String(),
		ClientType:                 s.store.Call("getItem", "client_type").String(),
		Network:                    network,
		VtxoTreeExpiry:             common.RelativeLocktime{Value: uint32(vtxoTreeExpiry), Type: vtxoTreeExpiryType},
		RoundInterval:              int64(roundInterval),
		UnilateralExitDelay:        common.RelativeLocktime{Value: uint32(unilateralExitDelay), Type: unilateralExitDelayType},
		Dust:                       uint64(dust),
		ExplorerURL:                s.store.Call("getItem", "explorer_url").String(),
		ForfeitAddress:             s.store.Call("getItem", "forfeit_address").String(),
		BoardingDescriptorTemplate: s.store.Call("getItem", "boarding_descriptor_template").String(),
		WithTransactionFeed:        withTxFeed,
	}, nil
}

func (s *configStore) CleanData(ctx context.Context) error {
	if err := s.writeData(&storeData{}); err != nil {
		return fmt.Errorf("failed to write to store: %s", err)
	}
	return nil
}

func (s *configStore) Close() {}

func (s *configStore) writeData(data *storeData) error {
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
