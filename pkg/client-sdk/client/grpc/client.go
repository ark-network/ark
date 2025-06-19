package grpcclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type service struct {
	arkv1.ArkServiceClient
}

type grpcClient struct {
	conn *grpc.ClientConn
	svc  service
}

func NewClient(serverUrl string) (client.TransportClient, error) {
	if len(serverUrl) <= 0 {
		return nil, fmt.Errorf("missing server url")
	}

	port := 80
	creds := insecure.NewCredentials()
	serverUrl = strings.TrimPrefix(serverUrl, "http://")
	if strings.HasPrefix(serverUrl, "https://") {
		serverUrl = strings.TrimPrefix(serverUrl, "https://")
		creds = credentials.NewTLS(nil)
		port = 443
	}
	if !strings.Contains(serverUrl, ":") {
		serverUrl = fmt.Sprintf("%s:%d", serverUrl, port)
	}
	conn, err := grpc.NewClient(serverUrl, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}

	svc := service{arkv1.NewArkServiceClient(conn)}
	return &grpcClient{conn, svc}, nil
}

func (a *grpcClient) GetInfo(ctx context.Context) (*client.Info, error) {
	req := &arkv1.GetInfoRequest{}
	resp, err := a.svc.GetInfo(ctx, req)
	if err != nil {
		return nil, err
	}
	return &client.Info{
		PubKey:                  resp.GetPubkey(),
		VtxoTreeExpiry:          resp.GetVtxoTreeExpiry(),
		UnilateralExitDelay:     resp.GetUnilateralExitDelay(),
		RoundInterval:           resp.GetRoundInterval(),
		Network:                 resp.GetNetwork(),
		Dust:                    uint64(resp.GetDust()),
		BoardingExitDelay:       resp.GetBoardingExitDelay(),
		ForfeitAddress:          resp.GetForfeitAddress(),
		Version:                 resp.GetVersion(),
		MarketHourStartTime:     resp.GetMarketHour().GetNextStartTime(),
		MarketHourEndTime:       resp.GetMarketHour().GetNextEndTime(),
		MarketHourPeriod:        resp.GetMarketHour().GetPeriod(),
		MarketHourRoundInterval: resp.GetMarketHour().GetRoundInterval(),
		UtxoMinAmount:           resp.GetUtxoMinAmount(),
		UtxoMaxAmount:           resp.GetUtxoMaxAmount(),
		VtxoMinAmount:           resp.GetVtxoMinAmount(),
		VtxoMaxAmount:           resp.GetVtxoMaxAmount(),
	}, nil
}

func (a *grpcClient) RegisterIntent(
	ctx context.Context,
	signature, message string,
) (string, error) {
	req := &arkv1.RegisterIntentRequest{
		Intent: &arkv1.Bip322Signature{
			Message:   message,
			Signature: signature,
		},
	}

	resp, err := a.svc.RegisterIntent(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.GetIntentId(), nil
}

func (a *grpcClient) DeleteIntent(ctx context.Context, signature, message string) error {
	req := &arkv1.DeleteIntentRequest{
		Proof: &arkv1.Bip322Signature{
			Message:   message,
			Signature: signature,
		},
	}
	_, err := a.svc.DeleteIntent(ctx, req)
	return err
}

func (a *grpcClient) ConfirmRegistration(ctx context.Context, intentID string) error {
	req := &arkv1.ConfirmRegistrationRequest{
		IntentId: intentID,
	}
	_, err := a.svc.ConfirmRegistration(ctx, req)
	return err
}

func (a *grpcClient) SubmitTreeNonces(
	ctx context.Context, batchId, cosignerPubkey string, nonces tree.TreeNonces,
) error {
	var nonceBuffer bytes.Buffer

	if err := nonces.Encode(&nonceBuffer); err != nil {
		return err
	}

	serializedNonces := hex.EncodeToString(nonceBuffer.Bytes())

	req := &arkv1.SubmitTreeNoncesRequest{
		BatchId:    batchId,
		Pubkey:     cosignerPubkey,
		TreeNonces: serializedNonces,
	}

	if _, err := a.svc.SubmitTreeNonces(ctx, req); err != nil {
		return err
	}

	return nil
}

func (a *grpcClient) SubmitTreeSignatures(
	ctx context.Context, batchId, cosignerPubkey string, signatures tree.TreePartialSigs,
) error {
	var sigsBuffer bytes.Buffer

	if err := signatures.Encode(&sigsBuffer); err != nil {
		return err
	}

	serializedSigs := hex.EncodeToString(sigsBuffer.Bytes())

	req := &arkv1.SubmitTreeSignaturesRequest{
		BatchId:        batchId,
		Pubkey:         cosignerPubkey,
		TreeSignatures: serializedSigs,
	}

	if _, err := a.svc.SubmitTreeSignatures(ctx, req); err != nil {
		return err
	}

	return nil
}

func (a *grpcClient) SubmitSignedForfeitTxs(
	ctx context.Context, signedForfeitTxs []string, signedCommitmentTx string,
) error {
	req := &arkv1.SubmitSignedForfeitTxsRequest{
		SignedForfeitTxs:   signedForfeitTxs,
		SignedCommitmentTx: signedCommitmentTx,
	}

	_, err := a.svc.SubmitSignedForfeitTxs(ctx, req)
	return err
}

func (a *grpcClient) GetEventStream(ctx context.Context) (<-chan client.BatchEventChannel, func(), error) {
	ctx, cancel := context.WithCancel(ctx)

	stream, err := a.svc.GetEventStream(ctx, &arkv1.GetEventStreamRequest{})
	if err != nil {
		cancel()
		return nil, nil, err
	}

	eventsCh := make(chan client.BatchEventChannel)

	go func() {
		defer close(eventsCh)

		for {
			resp, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					eventsCh <- client.BatchEventChannel{Err: client.ErrConnectionClosedByServer}
					return
				}
				if st, ok := status.FromError(err); ok && st.Code() == codes.Canceled {
					return
				}
				eventsCh <- client.BatchEventChannel{Err: err}
				return
			}

			ev, err := event{resp}.toBatchEvent()
			if err != nil {
				eventsCh <- client.BatchEventChannel{Err: err}
				return
			}

			eventsCh <- client.BatchEventChannel{Event: ev}
		}
	}()

	closeFn := func() {
		if err := stream.CloseSend(); err != nil {
			logrus.Warnf("failed to close event stream: %s", err)
		}
		cancel()
	}

	return eventsCh, closeFn, nil
}

func (a *grpcClient) SubmitTx(
	ctx context.Context, signedArkTx string, checkpointTxs []string,
) (string, string, []string, error) {
	req := &arkv1.SubmitTxRequest{
		SignedArkTx:   signedArkTx,
		CheckpointTxs: checkpointTxs,
	}

	resp, err := a.svc.SubmitTx(ctx, req)
	if err != nil {
		return "", "", nil, err
	}

	return resp.GetArkTxid(), resp.GetFinalArkTx(), resp.GetSignedCheckpointTxs(), nil
}

func (a *grpcClient) FinalizeTx(
	ctx context.Context, arkTxid string, finalCheckpointTxs []string,
) error {
	req := &arkv1.FinalizeTxRequest{
		ArkTxid:            arkTxid,
		FinalCheckpointTxs: finalCheckpointTxs,
	}

	_, err := a.svc.FinalizeTx(ctx, req)
	return err
}

func (c *grpcClient) GetTransactionsStream(
	ctx context.Context,
) (<-chan client.TransactionEvent, func(), error) {
	ctx, cancel := context.WithCancel(ctx)

	stream, err := c.svc.GetTransactionsStream(ctx, &arkv1.GetTransactionsStreamRequest{})
	if err != nil {
		cancel()
		return nil, nil, err
	}

	eventsCh := make(chan client.TransactionEvent)

	go func() {
		defer close(eventsCh)

		for {
			resp, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					eventsCh <- client.TransactionEvent{Err: client.ErrConnectionClosedByServer}
					return
				}
				if st, ok := status.FromError(err); ok && st.Code() == codes.Canceled {
					return
				}
				eventsCh <- client.TransactionEvent{Err: err}
				return
			}

			switch tx := resp.Tx.(type) {
			case *arkv1.GetTransactionsStreamResponse_CommitmentTx:
				eventsCh <- client.TransactionEvent{
					CommitmentTx: &client.TxNotification{
						Txid:           tx.CommitmentTx.Txid,
						SpentVtxos:     vtxos(tx.CommitmentTx.SpentVtxos).toVtxos(),
						SpendableVtxos: vtxos(tx.CommitmentTx.SpendableVtxos).toVtxos(),
						TxHex:          tx.CommitmentTx.GetHex(),
					},
				}
			case *arkv1.GetTransactionsStreamResponse_ArkTx:
				eventsCh <- client.TransactionEvent{
					ArkTx: &client.TxNotification{
						Txid:           tx.ArkTx.Txid,
						SpentVtxos:     vtxos(tx.ArkTx.SpentVtxos).toVtxos(),
						SpendableVtxos: vtxos(tx.ArkTx.SpendableVtxos).toVtxos(),
						TxHex:          tx.ArkTx.GetHex(),
					},
				}
			}
		}
	}()

	closeFn := func() {
		if err := stream.CloseSend(); err != nil {
			logrus.Warnf("failed to close transaction stream: %v", err)
		}
		cancel()
	}

	return eventsCh, closeFn, nil
}

func (c *grpcClient) Close() {
	//nolint:all
	c.conn.Close()
}
