package oceanwallet

import (
	"context"
	"io"
	"strings"
	"time"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type service struct {
	addr          string
	conn          *grpc.ClientConn
	walletClient  pb.WalletServiceClient
	accountClient pb.AccountServiceClient
	txClient      pb.TransactionServiceClient
	notifyClient  pb.NotificationServiceClient
	chVtxos       chan map[string]ports.VtxoWithValue
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
	chVtxos := make(chan map[string]ports.VtxoWithValue)
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

	isReady := false

	for !isReady {
		status, err := svc.Status(ctx)
		if err != nil {
			return nil, err
		}

		isReady = status.IsInitialized() && status.IsUnlocked()

		if !isReady {
			log.Info("Wallet must be initialized and unlocked to proceed. Waiting for wallet to be ready...")
			time.Sleep(3 * time.Second)
		}
	}

	// Create ark account at startup if needed.
	info, err := walletClient.GetInfo(ctx, &pb.GetInfoRequest{})
	if err != nil {
		return nil, err
	}

	mainAccountFound, connectorAccountFound := false, false

	for _, account := range info.GetAccounts() {
		if account.GetLabel() == arkAccount {
			mainAccountFound = true
			continue
		}

		if account.GetLabel() == connectorAccount {
			connectorAccountFound = true
			continue
		}

		if mainAccountFound && connectorAccountFound {
			break
		}
	}
	if !mainAccountFound {
		if _, err := accountClient.CreateAccountBIP44(ctx, &pb.CreateAccountBIP44Request{
			Label:          arkAccount,
			Unconfidential: true,
		}); err != nil {
			return nil, err
		}
	}

	if !connectorAccountFound {
		if _, err := accountClient.CreateAccountBIP44(ctx, &pb.CreateAccountBIP44Request{
			Label:          connectorAccount,
			Unconfidential: true,
		}); err != nil {
			return nil, err
		}
	}

	go svc.listenToNotifications()

	return svc, nil
}

func (s *service) Close() {
	close(s.chVtxos)
	s.conn.Close()
}

func (s *service) listenToNotifications() {
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
			if err == io.EOF || status.Convert(err).Code() == codes.Canceled {
				return
			}
			log.WithError(err).Warn("received unexpected error from source")
			return
		}

		if msg.GetEventType() != pb.UtxoEventType_UTXO_EVENT_TYPE_NEW &&
			msg.GetEventType() != pb.UtxoEventType_UTXO_EVENT_TYPE_CONFIRMED {
			continue
		}
		vtxos := toVtxos(msg.GetUtxos())
		if len(vtxos) > 0 {
			s.chVtxos <- vtxos
		}
	}
}

func toVtxos(utxos []*pb.Utxo) map[string]ports.VtxoWithValue {
	vtxos := make(map[string]ports.VtxoWithValue, len(utxos))
	for _, utxo := range utxos {
		// We want to notify for activity related to vtxos owner, therefore we skip
		// returning anything related to the internal accounts of the wallet, like
		// for example bip84-account0.
		if strings.HasPrefix(utxo.GetAccountName(), "bip") {
			continue
		}

		vtxos[utxo.Script] = ports.VtxoWithValue{
			VtxoKey: domain.VtxoKey{Txid: utxo.GetTxid(),
				VOut: utxo.GetIndex(),
			},
			Value: utxo.GetValue(),
		}
	}
	return vtxos
}
