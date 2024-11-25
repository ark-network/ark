//go:build js && wasm
// +build js,wasm

package browser

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"syscall/js"

	walletstore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type walletData struct {
	EncryptedPrvkey string `json:"encrypted_private_key"`
	PasswordHash    string `json:"password_hash"`
	PubKey          string `json:"pubkey"`
}

func (d walletData) decode() *walletstore.WalletData {
	encryptedPrvkey, _ := hex.DecodeString(d.EncryptedPrvkey)
	passwordHash, _ := hex.DecodeString(d.PasswordHash)
	buf, _ := hex.DecodeString(d.PubKey)
	pubkey, _ := secp256k1.ParsePubKey(buf)
	return &walletstore.WalletData{
		EncryptedPrvkey: encryptedPrvkey,
		PasswordHash:    passwordHash,
		PubKey:          pubkey,
	}
}

type walletStore struct {
	store js.Value
}

func NewLocalStorageWalletStore() (walletstore.WalletStore, error) {
	store := js.Global().Get("localStorage")
	return &walletStore{store}, nil
}

func (s *walletStore) AddWallet(data walletstore.WalletData) error {
	wd := &walletData{
		EncryptedPrvkey: hex.EncodeToString(data.EncryptedPrvkey),
		PasswordHash:    hex.EncodeToString(data.PasswordHash),
		PubKey:          hex.EncodeToString(data.PubKey.SerializeCompressed()),
	}

	if err := s.writeData(wd); err != nil {
		return fmt.Errorf("failed to write to file store: %s", err)
	}
	return nil
}

func (s *walletStore) GetWallet() (*walletstore.WalletData, error) {
	data := walletData{
		EncryptedPrvkey: s.store.Call("getItem", "encrypted_private_key").String(),
		PasswordHash:    s.store.Call("getItem", "password_hash").String(),
		PubKey:          s.store.Call("getItem", "pubkey").String(),
	}
	return data.decode(), nil
}

func (s *walletStore) writeData(data *walletData) error {
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
