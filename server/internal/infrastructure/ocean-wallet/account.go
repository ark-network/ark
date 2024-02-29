package oceanwallet

import (
	"context"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/vulpemventures/go-elements/address"
)

func (s *service) DeriveAddresses(
	ctx context.Context, numOfAddresses int,
) ([]string, error) {
	return s.deriveAddresses(ctx, numOfAddresses, arkAccount)
}

func (s *service) DeriveConnectorAddress(ctx context.Context) (string, error) {
	addresses, err := s.deriveAddresses(ctx, 1, connectorAccount)
	if err != nil {
		return "", err
	}

	return addresses[0], nil
}

func (s *service) ListConnectorUtxos(
	ctx context.Context, connectorAddress string,
) ([]ports.TxInput, error) {
	res, err := s.accountClient.ListUtxos(ctx, &pb.ListUtxosRequest{
		AccountName: connectorAccount,
		Addresses:   []string{connectorAddress},
	})
	if err != nil {
		return nil, err
	}

	utxos := make([]ports.TxInput, 0)
	for _, utxo := range res.GetSpendableUtxos().GetUtxos() {
		utxos = append(utxos, utxo)
	}
	for _, utxo := range res.GetLockedUtxos().GetUtxos() {
		utxos = append(utxos, utxo)
	}
	for _, utxo := range res.GetUnconfirmedUtxos().GetUtxos() {
		utxos = append(utxos, utxo)
	}

	return utxos, nil
}

func (s *service) deriveAddresses(
	ctx context.Context, numOfAddresses int, account string,
) ([]string, error) {
	res, err := s.accountClient.DeriveAddresses(ctx, &pb.DeriveAddressesRequest{
		AccountName:    account,
		NumOfAddresses: uint64(numOfAddresses),
	})
	if err != nil {
		return nil, err
	}
	addresses := make([]string, 0, numOfAddresses)
	for _, addr := range res.GetAddresses() {
		if isConf, _ := address.IsConfidential(addr); !isConf {
			addresses = append(addresses, addr)
			continue
		}
		info, _ := address.FromConfidential(addr)
		addresses = append(addresses, info.Address)
	}
	return addresses, nil
}
