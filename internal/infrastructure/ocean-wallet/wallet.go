package oceanwallet

import (
	"context"
	"strings"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/ports"
	"google.golang.org/grpc"
)

const accountLabel = "ark"

type wallet struct {
	client        pb.WalletServiceClient
	accountClient pb.AccountServiceClient
}

func newWallet(conn *grpc.ClientConn) *wallet {
	return &wallet{
		pb.NewWalletServiceClient(conn),
		pb.NewAccountServiceClient(conn),
	}
}

func (m *wallet) GenSeed(ctx context.Context) ([]string, error) {
	res, err := m.client.GenSeed(ctx, &pb.GenSeedRequest{})
	if err != nil {
		return nil, err
	}
	mnemonic := strings.Split(res.GetMnemonic(), " ")

	return mnemonic, nil
}

func (m *wallet) InitWallet(
	ctx context.Context, mnemonic []string, password string,
) error {
	_, err := m.client.CreateWallet(ctx, &pb.CreateWalletRequest{
		Mnemonic: strings.Join(mnemonic, " "),
		Password: password,
	})
	return err
}

func (m *wallet) Unlock(ctx context.Context, password string) error {
	if _, err := m.client.Unlock(ctx, &pb.UnlockRequest{
		Password: password,
	}); err != nil {
		return err
	}
	// Let's always make sure the 'ark' account is created after unlocking.
	info, err := m.client.GetInfo(ctx, &pb.GetInfoRequest{})
	if err != nil {
		return err
	}
	if len(info.GetAccounts()) <= 0 {
		_, err := m.accountClient.CreateAccountBIP44(
			ctx, &pb.CreateAccountBIP44Request{
				Label: accountLabel,
			},
		)
		return err
	}
	return nil
}

func (m *wallet) Lock(ctx context.Context, password string) error {
	_, err := m.client.Lock(ctx, &pb.LockRequest{
		Password: password,
	})
	return err
}

func (m *wallet) Status(
	ctx context.Context,
) (ports.WalletStatus, error) {
	res, err := m.client.Status(ctx, &pb.StatusRequest{})
	if err != nil {
		return nil, err
	}
	return walletStatus{res}, nil
}

type walletStatus struct {
	*pb.StatusResponse
}

func (w walletStatus) IsInitialized() bool {
	return w.StatusResponse.GetInitialized()
}
func (w walletStatus) IsUnlocked() bool {
	return w.StatusResponse.GetUnlocked()
}
func (w walletStatus) IsSynced() bool {
	return w.StatusResponse.GetSynced()
}
