package inmemorystore

import (
	"context"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type WalletStore struct {
	privateKey *secp256k1.PrivateKey
}

func (i *WalletStore) CreatePrivateKey(
	ctx context.Context,
) (*secp256k1.PrivateKey, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func (i *WalletStore) GetPrivateKeyHex(ctx context.Context) (string, error) {
	if i.privateKey == nil {
		return "", nil
	}

	return hex.EncodeToString(i.privateKey.Serialize()), nil
}

func (i *WalletStore) Save(ctx context.Context) error {
	return nil
}
