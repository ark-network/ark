package oceanwallet

import (
	"context"
	"errors"
	"io"
	"strings"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
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
	chVtxos       chan map[string][]ports.VtxoWithValue
	isListening   bool
	syncedCh      chan struct{}
}

func NewService(addr string) (ports.WalletService, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	walletClient := pb.NewWalletServiceClient(conn)
	accountClient := pb.NewAccountServiceClient(conn)
	txClient := pb.NewTransactionServiceClient(conn)
	notifyClient := pb.NewNotificationServiceClient(conn)
	chVtxos := make(chan map[string][]ports.VtxoWithValue)
	svc := &service{
		addr:          addr,
		conn:          conn,
		walletClient:  walletClient,
		accountClient: accountClient,
		txClient:      txClient,
		notifyClient:  notifyClient,
		chVtxos:       chVtxos,
		syncedCh:      make(chan struct{}),
	}

	ctx := context.Background()

	status, err := svc.Status(ctx)
	if err != nil {
		return nil, err
	}

	if status.IsUnlocked() {
		go svc.listenToNotifications()
	}

	return svc, nil
}

func (s *service) Close() {
	close(s.chVtxos)
	s.conn.Close()
}

func (s *service) GetSyncedUpdate(_ context.Context) <-chan struct{} {
	return s.syncedCh
}

func (s *service) GenSeed(ctx context.Context) (string, error) {
	res, err := s.walletClient.GenSeed(ctx, &pb.GenSeedRequest{})
	if err != nil {
		return "", err
	}
	return res.GetMnemonic(), nil
}

func (s *service) Create(ctx context.Context, seed, password string) error {
	_, err := s.walletClient.CreateWallet(ctx, &pb.CreateWalletRequest{
		Mnemonic: seed,
		Password: password,
	})
	return err
}

func (s *service) Restore(ctx context.Context, seed, password string) error {
	_, err := s.walletClient.RestoreWallet(ctx, &pb.RestoreWalletRequest{
		Mnemonic: seed,
		Password: password,
	})
	return err
}

func (s *service) Unlock(ctx context.Context, password string) error {
	if _, err := s.walletClient.Unlock(ctx, &pb.UnlockRequest{
		Password: password,
	}); err != nil {
		return err
	}

	info, err := s.walletClient.GetInfo(ctx, &pb.GetInfoRequest{})
	if err != nil {
		return err
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
		if _, err := s.accountClient.CreateAccountBIP44(ctx, &pb.CreateAccountBIP44Request{
			Label:          arkAccount,
			Unconfidential: true,
		}); err != nil {
			return err
		}
	}

	if !connectorAccountFound {
		if _, err := s.accountClient.CreateAccountBIP44(ctx, &pb.CreateAccountBIP44Request{
			Label:          connectorAccount,
			Unconfidential: true,
		}); err != nil {
			return err
		}
	}

	if !s.isListening {
		go s.listenToNotifications()
	}
	return err
}

func (s *service) Lock(ctx context.Context, password string) error {
	_, err := s.walletClient.Lock(ctx, &pb.LockRequest{
		Password: password,
	})
	return err
}

func (s *service) GetDustAmount(ctx context.Context) (uint64, error) {
	return 450, nil // constant on liquid cause fees are not subject to huge changes
}

func (s *service) SignMessage(ctx context.Context, message []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (s *service) VerifyMessageSignature(ctx context.Context, message, signature []byte) (bool, error) {
	return false, errors.New("not implemented")
}

func (s *service) listenToNotifications() {
	s.isListening = true
	defer func() {
		s.isListening = false
	}()

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

func toVtxos(utxos []*pb.Utxo) map[string][]ports.VtxoWithValue {
	vtxos := make(map[string][]ports.VtxoWithValue, len(utxos))
	for _, utxo := range utxos {
		// We want to notify for activity related to vtxos owner, therefore we skip
		// returning anything related to the internal accounts of the wallet, like
		// for example bip84-account0.
		if strings.HasPrefix(utxo.GetAccountName(), "bip") {
			continue
		}

		vtxos[utxo.Script] = []ports.VtxoWithValue{
			{
				VtxoKey: domain.VtxoKey{Txid: utxo.GetTxid(),
					VOut: utxo.GetIndex(),
				},
				Value: utxo.GetValue(),
			},
		}
	}
	return vtxos
}
