package arksdkwasm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"syscall/js"

	"github.com/ark-network/ark-sdk/internal/utils"
	"github.com/ark-network/ark-sdk/store"
	walletstore "github.com/ark-network/ark-sdk/wallet/singlekey/store"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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

type walletData struct {
	EncryptedPrvkey string `json:"encrypted_private_key"`
	PasswordHash    string `json:"password_hash"`
	Pubkey          string `json:"pubkey"`
}

func (d walletData) decode() *walletstore.WalletData {
	encryptedPrvkey, _ := hex.DecodeString(d.EncryptedPrvkey)
	passwordHash, _ := hex.DecodeString(d.PasswordHash)
	buf, _ := hex.DecodeString(d.Pubkey)
	pubkey, _ := secp256k1.ParsePubKey(buf)
	return &walletstore.WalletData{
		EncryptedPrvkey: encryptedPrvkey,
		PasswordHash:    passwordHash,
		Pubkey:          pubkey,
	}
}

type localStorageStore struct {
	store js.Value
}

func NewLocalStorageStore() (walletstore.WalletStore, error) {
	store := js.Global().Get("localStorage")
	return &localStorageStore{store}, nil
}

func (s *localStorageStore) AddData(ctx context.Context, data store.StoreData) error {
	sd := &storeData{
		AspUrl:              data.AspUrl,
		AspPubkey:           hex.EncodeToString(data.AspPubkey.SerializeCompressed()),
		WalletType:          data.WalletType,
		ClientType:          data.ClientType,
		ExplorerURL:         data.ExplorerURL,
		Network:             data.Network.Name,
		RoundLifetime:       fmt.Sprintf("%d", data.RoundLifetime),
		UnilateralExitDelay: fmt.Sprintf("%d", data.UnilateralExitDelay),
		MinRelayFee:         fmt.Sprintf("%d", data.MinRelayFee),
	}
	return s.writeStoreData(sd)
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
		ExplorerURL:         s.store.Call("getItem", "explorer_url").String(),
		Network:             network,
		RoundLifetime:       int64(roundLifetime),
		UnilateralExitDelay: int64(unilateralExitDelay),
		MinRelayFee:         uint64(minRelayFee),
	}, nil
}

func (s *localStorageStore) CleanData(ctx context.Context) error {
	if err := s.writeStoreData(&storeData{}); err != nil {
		return fmt.Errorf("failed to write to store: %s", err)
	}
	return nil
}

func (s *localStorageStore) AddWallet(data walletstore.WalletData) error {
	wd := &walletData{
		EncryptedPrvkey: hex.EncodeToString(data.EncryptedPrvkey),
		PasswordHash:    hex.EncodeToString(data.PasswordHash),
		Pubkey:          hex.EncodeToString(data.Pubkey.SerializeCompressed()),
	}

	if err := s.writeWalletData(wd); err != nil {
		return fmt.Errorf("failed to write to file store: %s", err)
	}
	return nil
}

func (s *localStorageStore) GetWallet() (*walletstore.WalletData, error) {
	data := walletData{
		EncryptedPrvkey: s.store.Call("getItem", "encrypted_private_key").String(),
		PasswordHash:    s.store.Call("getItem", "password_hash").String(),
		Pubkey:          s.store.Call("getItem", "pubkey").String(),
	}
	return data.decode(), nil
}

func (s *localStorageStore) writeStoreData(data *storeData) error {
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

func (s *localStorageStore) writeWalletData(data *walletData) error {
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
