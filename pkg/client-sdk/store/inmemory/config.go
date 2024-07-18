package inmemorystore

import (
	"context"
	"errors"

	arksdk "github.com/ark-network/ark-sdk"
)

type configStore struct {
	aspUrl   string
	protocol arksdk.TransportProtocol

	explorerUrl  string
	net          string
	aspPubKeyHex string
}

func New(
	aspUrl string, protocol arksdk.TransportProtocol,
) (arksdk.ConfigStore, error) {
	if aspUrl == "" {
		return nil, errors.New("aspUrl cannot be empty")
	}

	if protocol != arksdk.Rest && protocol != arksdk.Grpc {
		return nil, errors.New("invalid protocol")
	}

	return &configStore{
		aspUrl:   aspUrl,
		protocol: protocol,
	}, nil
}

func (s *configStore) GetAspUrl(ctx context.Context) (string, error) {
	return s.aspUrl, nil
}

func (s *configStore) GetAspPubKeyHex(ctx context.Context) (string, error) {
	return s.aspPubKeyHex, nil
}

func (s *configStore) GetTransportProtocol(ctx context.Context) (arksdk.TransportProtocol, error) {
	return s.protocol, nil
}

func (s *configStore) GetExplorerUrl(ctx context.Context) (string, error) {
	return s.explorerUrl, nil
}

func (s *configStore) GetNetwork(ctx context.Context) (string, error) {
	return s.net, nil
}

func (s *configStore) SetAspUrl(aspUrl string) {
	s.aspUrl = aspUrl
}

func (s *configStore) SetAspPubKeyHex(aspPubKeyHex string) {
	s.aspPubKeyHex = aspPubKeyHex
}

func (s *configStore) SetTransportProtocol(protocol arksdk.TransportProtocol) {
	s.protocol = protocol
}

func (s *configStore) SetExplorerUrl(explorerUrl string) {
	s.explorerUrl = explorerUrl
}

func (s *configStore) SetNetwork(net string) {
	s.net = net
}

func (s *configStore) Save(ctx context.Context) error {
	return nil // Implement save logic if needed
}
