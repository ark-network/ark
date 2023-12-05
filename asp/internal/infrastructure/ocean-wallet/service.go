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
	status, err := svc.Status(context.Background())
	if err != nil {
		return nil, err
	}
	if !(status.IsInitialized() && status.IsUnlocked()) {
		return nil, fmt.Errorf("wallet must be already initialized and unlocked")
	}

	return svc, nil
}

func (s *service) Close() {
	s.conn.Close()
}
