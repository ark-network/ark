package store

import (
	"context"

	arksdk "github.com/ark-network/ark-sdk"
)

type InMemoryConfigStore struct {
	ExplorerUrl  string
	Protocol     arksdk.TransportProtocol
	Net          string
	AspUrl       string
	AspPubKeyHex string
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
