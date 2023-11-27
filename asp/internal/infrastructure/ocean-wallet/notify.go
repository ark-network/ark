package oceanwallet

import (
	"context"
	"fmt"
	"io"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/ports"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type notify struct {
	client              pb.NotificationServiceClient
	chTxNotifications   chan ports.WalletTxNotification
	chUtxoNotifications chan ports.WalletUtxoNotification
}

func newNotify(conn *grpc.ClientConn) (*notify, error) {
	svc := &notify{
		client:              pb.NewNotificationServiceClient(conn),
		chTxNotifications:   make(chan ports.WalletTxNotification),
		chUtxoNotifications: make(chan ports.WalletUtxoNotification),
	}

	txStream, err := svc.client.TransactionNotifications(
		context.Background(), &pb.TransactionNotificationsRequest{},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to open stream for tx notifications: %s", err,
		)
	}
	go svc.startListeningForTxNotifications(txStream)

	utxoStream, err := svc.client.UtxosNotifications(
		context.Background(), &pb.UtxosNotificationsRequest{},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to open stream for utxo notifications: %s", err,
		)
	}
	go svc.startListeningForUtxoNotifications(utxoStream)

	return svc, nil
}

func (m *notify) GetTxNotifications() chan ports.WalletTxNotification {
	return m.chTxNotifications
}

func (m *notify) GetUtxoNotifications() chan ports.WalletUtxoNotification {
	return m.chUtxoNotifications
}

func (m *notify) startListeningForTxNotifications(
	stream pb.NotificationService_TransactionNotificationsClient,
) {
	var err error
	defer func() {
		if err != nil {
			log.WithError(err).Fatal(
				"notification handler: error while listenting to tx notifications",
			)
		}
	}()

	for {
		var notification *pb.TransactionNotificationsResponse
		notification, err = stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return
		}

		select {
		case m.chTxNotifications <- txNotifyInfo{notification}:
			continue
		default:
		}
	}
}

func (m *notify) startListeningForUtxoNotifications(
	stream pb.NotificationService_UtxosNotificationsClient,
) {
	var err error
	defer func() {
		if err != nil {
			log.WithError(err).Fatal(
				"notification handler: error while listenting to utxo notifications",
			)
		}
	}()

	for {
		var notification *pb.UtxosNotificationsResponse
		notification, err = stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return
		}

		select {
		case m.chUtxoNotifications <- utxoNotifyInfo{notification}:
			continue
		default:
		}
	}
}

type txNotifyInfo struct {
	*pb.TransactionNotificationsResponse
}

func (i txNotifyInfo) GetEventType() ports.WalletTxEventType {
	return txEventType(i.TransactionNotificationsResponse.GetEventType())
}
func (i txNotifyInfo) GetTxHex() string {
	return i.TransactionNotificationsResponse.GetTxhex()
}
func (i txNotifyInfo) GetBlockDetails() ports.BlockInfo {
	return i.TransactionNotificationsResponse.GetBlockDetails()
}

type txEventType pb.TxEventType

func (t txEventType) IsUnconfirmed() bool {
	return int(t) == int(pb.TxEventType_TX_EVENT_TYPE_UNCONFIRMED)
}
func (t txEventType) IsConfirmed() bool {
	return int(t) == int(pb.TxEventType_TX_EVENT_TYPE_CONFIRMED)
}
func (t txEventType) IsBroadcasted() bool {
	return int(t) == int(pb.TxEventType_TX_EVENT_TYPE_BROADCASTED)
}

type utxoNotifyInfo struct {
	*pb.UtxosNotificationsResponse
}

func (i utxoNotifyInfo) GetEventType() ports.WalletUtxoEventType {
	return utxoEventType(i.UtxosNotificationsResponse.GetEventType())
}
func (i utxoNotifyInfo) GetUtxos() []ports.Utxo {
	utxos := make([]ports.Utxo, 0, len(i.UtxosNotificationsResponse.GetUtxos()))
	for _, u := range i.UtxosNotificationsResponse.GetUtxos() {
		utxos = append(utxos, utxoInfo{u})
	}
	return utxos
}

type utxoEventType pb.UtxoEventType

func (t utxoEventType) IsUnconfirmed() bool {
	return int(t) == int(pb.UtxoEventType_UTXO_EVENT_TYPE_NEW)
}
func (t utxoEventType) IsSpent() bool {
	return int(t) == int(pb.UtxoEventType_UTXO_EVENT_TYPE_SPENT)
}
func (t utxoEventType) IsConfirmed() bool {
	return int(t) == int(pb.UtxoEventType_UTXO_EVENT_TYPE_CONFIRMED)
}
func (t utxoEventType) IsLocked() bool {
	return int(t) == int(pb.UtxoEventType_UTXO_EVENT_TYPE_LOCKED)
}
func (t utxoEventType) IsUnlocked() bool {
	return int(t) == int(pb.UtxoEventType_UTXO_EVENT_TYPE_UNLOCKED)
}

type utxoInfo struct {
	*pb.Utxo
}

func (i utxoInfo) GetConfirmedStatus() ports.UtxoStatus {
	return utxoStatusInfo{i.Utxo.GetConfirmedStatus()}
}

func (i utxoInfo) GetSpentStatus() ports.UtxoStatus {
	return utxoStatusInfo{i.Utxo.GetSpentStatus()}
}

type utxoStatusInfo struct {
	*pb.UtxoStatus
}

func (i utxoStatusInfo) GetBlockInfo() ports.BlockInfo {
	return i.UtxoStatus.GetBlockInfo()
}
