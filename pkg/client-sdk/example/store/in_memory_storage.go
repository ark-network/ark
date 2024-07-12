package store

import (
	"context"
	"encoding/hex"

	arksdk "github.com/ark-network/ark-sdk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type InMemoryConfigStore struct {
	ExplorerUrl         string
	Protocol            arksdk.TransportProtocol
	Net                 string
	AspUrl              string
	AspPubKeyHex        string
	RoundLifeTime       int
	UnilateralExitDelay int
}

func (store *InMemoryConfigStore) GetAspUrl(ctx context.Context) (string, error) {
	return store.AspUrl, nil
}

func (store *InMemoryConfigStore) GetAspPubKeyHex(ctx context.Context) (string, error) {
	return store.AspPubKeyHex, nil
}

func (store *InMemoryConfigStore) GetTransportProtocol(ctx context.Context) (arksdk.TransportProtocol, error) {
	return store.Protocol, nil
}

func (store *InMemoryConfigStore) GetExplorerUrl(ctx context.Context) (string, error) {
	return store.ExplorerUrl, nil
}

func (store *InMemoryConfigStore) GetNetwork(ctx context.Context) (string, error) {
	return store.Net, nil
}

func (store *InMemoryConfigStore) Save(ctx context.Context) error {
	return nil // Implement save logic if needed
}

type InMemoryWalletStore struct {
	privateKey *secp256k1.PrivateKey
}

func (i *InMemoryWalletStore) CreatePrivateKey(
	ctx context.Context,
) (*secp256k1.PrivateKey, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func (i *InMemoryWalletStore) GetPrivateKeyHex(ctx context.Context) (string, error) {
	if i.privateKey == nil {
		return "", nil
	}

	return hex.EncodeToString(i.privateKey.Serialize()), nil
}

func (i *InMemoryWalletStore) Save(ctx context.Context) error {
	return nil
}
