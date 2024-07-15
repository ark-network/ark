package inmemorystore

import (
	"context"
	"encoding/hex"

	arksdk "github.com/ark-network/ark-sdk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type walletStore struct {
	privateKey *secp256k1.PrivateKey
}

func NewWalletStore() arksdk.WalletStore {
	return &walletStore{}
}

func (w *walletStore) CreatePrivateKey() (*secp256k1.PrivateKey, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	w.privateKey = privKey

	return privKey, nil
}

func (w *walletStore) GetPrivateKeyHex() (string, error) {
	if w.privateKey == nil {
		return "", nil
	}

	return hex.EncodeToString(w.privateKey.Serialize()), nil
}

func (w *walletStore) Save(ctx context.Context) error {
	return nil
}
