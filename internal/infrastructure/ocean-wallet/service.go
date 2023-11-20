package oceanwallet

import (
	"context"

	"github.com/ark-network/ark/internal/core/ports"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type service struct {
	addr string
	conn *grpc.ClientConn

	wallet  *wallet
	account *account
	tx      *tx
	notify  *notify
}

func NewService(addr string) (ports.WalletService, error) {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	svc := &service{
		addr:    addr,
		conn:    conn,
		wallet:  newWallet(conn),
		account: newAccount(conn),
		tx:      newTx(conn),
	}
	if _, err := svc.Wallet().Status(context.Background()); err != nil {
		return nil, err
	}
	svc.notify, _ = newNotify(conn)

	return svc, nil
}

func (s *service) Wallet() ports.Wallet {
	return s.wallet
}

func (s *service) Account() ports.Account {
	return s.account
}

func (s *service) Transaction() ports.Transaction {
	return s.tx
}

func (s *service) Notification() ports.Notification {
	return s.notify
}

func (s *service) Close() {
	s.conn.Close()
}
