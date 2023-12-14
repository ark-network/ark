package oceanwallet

import (
	"context"
	"fmt"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/ports"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type service struct {
	addr          string
	conn          *grpc.ClientConn
	walletClient  pb.WalletServiceClient
	accountClient pb.AccountServiceClient
	txClient      pb.TransactionServiceClient
}

func NewService(addr string) (ports.WalletService, error) {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	walletClient := pb.NewWalletServiceClient(conn)
	accountClient := pb.NewAccountServiceClient(conn)
	txClient := pb.NewTransactionServiceClient(conn)
	svc := &service{
		addr:          addr,
		conn:          conn,
		walletClient:  walletClient,
		accountClient: accountClient,
		txClient:      txClient,
	}

	ctx := context.Background()
	status, err := svc.Status(ctx)
	if err != nil {
		return nil, err
	}
	if !(status.IsInitialized() && status.IsUnlocked()) {
		return nil, fmt.Errorf("wallet must be already initialized and unlocked")
	}

	// Create ark account at startup if needed.
	info, err := walletClient.GetInfo(ctx, &pb.GetInfoRequest{})
	if err != nil {
		return nil, err
	}
	found := false
	for _, account := range info.GetAccounts() {
		if account.GetLabel() == accountLabel {
			found = true
			break
		}
	}
	if !found {
		if _, err := accountClient.CreateAccountBIP44(ctx, &pb.CreateAccountBIP44Request{
			Label:          accountLabel,
			Unconfidential: true,
		}); err != nil {
			return nil, err
		}
	}

	return svc, nil
}

func (s *service) Close() {
	s.conn.Close()
}
