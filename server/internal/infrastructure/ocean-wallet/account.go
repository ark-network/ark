package oceanwallet

import (
	"context"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
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

	return utxos, nil
}

func (s *service) ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error) {
	return s.getBalance(ctx, connectorAccount)
}

func (s *service) MainAccountBalance(ctx context.Context) (uint64, uint64, error) {
	return s.getBalance(ctx, arkAccount)
}

func (s *service) getBalance(ctx context.Context, accountName string) (uint64, uint64, error) {
	res, err := s.accountClient.Balance(ctx, &pb.BalanceRequest{
		AccountName: accountName,
	})
	if err != nil {
		return 0, 0, err
	}

	balances := res.GetBalance()
	available, locked := getLBTCbalance(balances)
	return available, locked, nil
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

func getLBTCbalance(balances map[string]*pb.BalanceInfo) (uint64, uint64) {
	liquidBalance, liquidLockedBalance, found := getBalance(balances, network.Liquid.AssetID)
	if found {
		return liquidBalance, liquidLockedBalance
	}

	testnetBalance, testnetLockedBalance, found := getBalance(balances, network.Testnet.AssetID)
	if found {
		return testnetBalance, testnetLockedBalance
	}

	regtestBalance, regtestLockedBalance, found := getBalance(balances, network.Regtest.AssetID)
	if found {
		return regtestBalance, regtestLockedBalance
	}

	return 0, 0
}

func getBalance(balances map[string]*pb.BalanceInfo, assetID string) (uint64, uint64, bool) {
	balance, ok := balances[assetID]
	if !ok {
		return 0, 0, false
	}

	return balance.GetConfirmedBalance() + balance.GetUnconfirmedBalance(), balance.GetLockedBalance(), true
}
