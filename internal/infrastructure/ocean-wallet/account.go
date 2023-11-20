package oceanwallet

import (
	"context"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/vulpemventures/go-elements/address"
	"google.golang.org/grpc"
)

type account struct {
	client pb.AccountServiceClient
}

func newAccount(conn *grpc.ClientConn) *account {
	return &account{pb.NewAccountServiceClient(conn)}
}

func (m *account) DeriveAddresses(
	ctx context.Context, numOfAddresses int,
) ([]string, error) {
	res, err := m.client.DeriveAddresses(ctx, &pb.DeriveAddressesRequest{
		AccountName:    accountLabel,
		NumOfAddresses: uint64(numOfAddresses),
	})
	if err != nil {
		return nil, err
	}
	// By default, ocean generates confidential addresses. Since we're going to
	// create unconfidential txs only, let's return unconf addresses.
	addresses := make([]string, 0, numOfAddresses)
	for _, addr := range res.GetAddresses() {
		info, _ := address.FromConfidential(addr)
		addresses = append(addresses, info.Address)
	}
	return addresses, nil
}

func (m *account) GetBalance(
	ctx context.Context,
) (map[string]ports.Balance, error) {
	res, err := m.client.Balance(ctx, &pb.BalanceRequest{
		AccountName: accountLabel,
	})
	if err != nil {
		return nil, err
	}
	balance := make(map[string]ports.Balance)
	for asset, bal := range res.GetBalance() {
		balance[asset] = bal
	}
	return balance, nil
}

func (m *account) ListUtxos(
	ctx context.Context,
) (spendableUtxos, lockedUtxos []ports.Utxo, err error) {
	res, err := m.client.ListUtxos(ctx, &pb.ListUtxosRequest{
		AccountName: accountLabel,
	})
	if err != nil {
		return nil, nil, err
	}
	if res.GetSpendableUtxos() != nil {
		spendableUtxos = utxoList(res.GetSpendableUtxos().GetUtxos()).toPortableList()
	}
	if res.GetLockedUtxos() != nil {
		lockedUtxos = utxoList(res.GetLockedUtxos().GetUtxos()).toPortableList()
	}
	return
}

type utxoList []*pb.Utxo

func (l utxoList) toPortableList() []ports.Utxo {
	utxos := make([]ports.Utxo, 0, len(l))
	for _, u := range l {
		utxos = append(utxos, utxoInfo{u})
	}
	return utxos
}
