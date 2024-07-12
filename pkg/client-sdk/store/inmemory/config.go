package inmemorystore

import (
	"context"

	arksdk "github.com/ark-network/ark-sdk"
)

type ConfigStore struct {
	ExplorerUrl  string
	Protocol     arksdk.TransportProtocol
	Net          string
	AspUrl       string
	AspPubKeyHex string
}

func (store *ConfigStore) GetAspUrl(ctx context.Context) (string, error) {
	return store.AspUrl, nil
}

func (store *ConfigStore) GetAspPubKeyHex(ctx context.Context) (string, error) {
	return store.AspPubKeyHex, nil
}

func (store *ConfigStore) GetTransportProtocol(ctx context.Context) (arksdk.TransportProtocol, error) {
	return store.Protocol, nil
}

func (store *ConfigStore) GetExplorerUrl(ctx context.Context) (string, error) {
	return store.ExplorerUrl, nil
}

func (store *ConfigStore) GetNetwork(ctx context.Context) (string, error) {
	return store.Net, nil
}

func (store *ConfigStore) Save(ctx context.Context) error {
	return nil // Implement save logic if needed
}
