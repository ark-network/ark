package oceanwallet

import (
	"context"
	"fmt"
	"io"
	"strings"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type service struct {
	addr          string
	conn          *grpc.ClientConn
	walletClient  pb.WalletServiceClient
	accountClient pb.AccountServiceClient
	txClient      pb.TransactionServiceClient
	notifyClient  pb.NotificationServiceClient
	chVtxos       chan []domain.VtxoKey
}

func NewService(addr string) (ports.WalletService, error) {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	walletClient := pb.NewWalletServiceClient(conn)
	accountClient := pb.NewAccountServiceClient(conn)
	txClient := pb.NewTransactionServiceClient(conn)
	notifyClient := pb.NewNotificationServiceClient(conn)
	chVtxos := make(chan []domain.VtxoKey)
	svc := &service{
		addr:          addr,
		conn:          conn,
		walletClient:  walletClient,
		accountClient: accountClient,
		txClient:      txClient,
		notifyClient:  notifyClient,
		chVtxos:       chVtxos,
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

	go svc.listenToNotificaitons()

	return svc, nil
}

func (s *service) Close() {
	close(s.chVtxos)
	s.conn.Close()
}

func (s *service) listenToNotificaitons() {
	var stream pb.NotificationService_UtxosNotificationsClient
	var err error
	for {
		stream, err = s.notifyClient.UtxosNotifications(context.Background(), &pb.UtxosNotificationsRequest{})
		if err != nil {
			continue
		}
		break
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return
			}
			log.WithError(err).Warn("received unexpected error from source")
			return
		}

		if msg.GetEventType() != pb.UtxoEventType_UTXO_EVENT_TYPE_SPENT {
			continue
		}
		vtxos := toVtxos(msg.GetUtxos())
		if len(vtxos) > 0 {
			go func() {
				s.chVtxos <- vtxos
			}()
		}
	}
}

func toVtxos(utxos []*pb.Utxo) []domain.VtxoKey {
	vtxos := make([]domain.VtxoKey, 0, len(utxos))
	for _, utxo := range utxos {
		// We want to notify for activity related to vtxos owner, therefore we skip
		// returning anything related to the internal accounts of the wallet, like
		// for example bip84-account0.
		if strings.HasPrefix(utxo.GetAccountName(), "bip") {
			continue
		}

		vtxos = append(vtxos, domain.VtxoKey{
			Txid: utxo.GetTxid(),
			VOut: utxo.GetIndex(),
		})
	}
	return vtxos
}
