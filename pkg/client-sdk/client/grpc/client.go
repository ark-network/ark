package grpcclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type service struct {
	arkv1.ArkServiceClient
	arkv1.ExplorerServiceClient
}

type grpcClient struct {
	conn      *grpc.ClientConn
	svc       service
	treeCache *utils.Cache[tree.TxTree]
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

	svc := service{arkv1.NewArkServiceClient(conn), arkv1.NewExplorerServiceClient(conn)}
	treeCache := utils.NewCache[tree.TxTree]()

	return &grpcClient{conn, svc, treeCache}, nil
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

func (a *grpcClient) GetBoardingAddress(
	ctx context.Context, userPubkey string,
) (string, error) {
	req := &arkv1.GetBoardingAddressRequest{
		Pubkey: userPubkey,
	}
	resp, err := a.svc.GetBoardingAddress(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.GetAddress(), nil
}

func (a *grpcClient) RegisterInputsForNextRound(
	ctx context.Context, inputs []client.Input,
) (string, error) {
	req := &arkv1.RegisterInputsForNextRoundRequest{
		Inputs: ins(inputs).toProto(),
	}

	resp, err := a.svc.RegisterInputsForNextRound(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.GetRequestId(), nil
}

func (a *grpcClient) RegisterIntent(
	ctx context.Context,
	signature, message string,
) (string, error) {
	req := &arkv1.RegisterIntentRequest{
		Bip322Signature: &arkv1.Bip322Signature{
			Message:   message,
			Signature: signature,
		},
	}

	resp, err := a.svc.RegisterIntent(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.GetRequestId(), nil
}

func (a *grpcClient) DeleteIntent(ctx context.Context, intentID, signature, message string) error {
	var req *arkv1.DeleteIntentRequest

	if intentID != "" {
		req = &arkv1.DeleteIntentRequest{
			Proof: &arkv1.DeleteIntentRequest_IntentId{
				IntentId: intentID,
			},
		}
	} else {
		req = &arkv1.DeleteIntentRequest{
			Proof: &arkv1.DeleteIntentRequest_Bip322Signature{
				Bip322Signature: &arkv1.Bip322Signature{
					Message:   message,
					Signature: signature,
				},
			},
		}
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

func (a *grpcClient) RegisterOutputsForNextRound(
	ctx context.Context, requestID string, outputs []client.Output, cosignersPublicKeys []string,
) error {
	req := &arkv1.RegisterOutputsForNextRoundRequest{
		RequestId: requestID,
		Outputs:   outs(outputs).toProto(),
	}
	if len(cosignersPublicKeys) > 0 {
		req.CosignersPublicKeys = cosignersPublicKeys
	}
	_, err := a.svc.RegisterOutputsForNextRound(ctx, req)
	return err
}

func (a *grpcClient) SubmitTreeNonces(
	ctx context.Context, roundID, cosignerPubkey string, nonces tree.TreeNonces,
) error {
	var nonceBuffer bytes.Buffer

	if err := nonces.Encode(&nonceBuffer); err != nil {
		return err
	}

	serializedNonces := hex.EncodeToString(nonceBuffer.Bytes())

	req := &arkv1.SubmitTreeNoncesRequest{
		RoundId:    roundID,
		Pubkey:     cosignerPubkey,
		TreeNonces: serializedNonces,
	}

	if _, err := a.svc.SubmitTreeNonces(ctx, req); err != nil {
		return err
	}

	return nil
}

func (a *grpcClient) SubmitTreeSignatures(
	ctx context.Context, roundID, cosignerPubkey string, signatures tree.TreePartialSigs,
) error {
	var sigsBuffer bytes.Buffer

	if err := signatures.Encode(&sigsBuffer); err != nil {
		return err
	}

	serializedSigs := hex.EncodeToString(sigsBuffer.Bytes())

	req := &arkv1.SubmitTreeSignaturesRequest{
		RoundId:        roundID,
		Pubkey:         cosignerPubkey,
		TreeSignatures: serializedSigs,
	}

	if _, err := a.svc.SubmitTreeSignatures(ctx, req); err != nil {
		return err
	}

	return nil
}

func (a *grpcClient) SubmitSignedForfeitTxs(
	ctx context.Context, signedForfeitTxs []string, signedRoundTx string,
) error {
	req := &arkv1.SubmitSignedForfeitTxsRequest{
		SignedForfeitTxs: signedForfeitTxs,
	}

	if len(signedRoundTx) > 0 {
		req.SignedRoundTx = &signedRoundTx
	}

	_, err := a.svc.SubmitSignedForfeitTxs(ctx, req)
	return err
}

func (a *grpcClient) GetEventStream(ctx context.Context) (<-chan client.RoundEventChannel, func(), error) {
	ctx, cancel := context.WithCancel(ctx)

	stream, err := a.svc.GetEventStream(ctx, &arkv1.GetEventStreamRequest{})
	if err != nil {
		cancel()
		return nil, nil, err
	}

	eventsCh := make(chan client.RoundEventChannel)

	go func() {
		defer close(eventsCh)

		for {
			resp, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					eventsCh <- client.RoundEventChannel{Err: client.ErrConnectionClosedByServer}
					return
				}
				if st, ok := status.FromError(err); ok && st.Code() == codes.Canceled {
					return
				}
				eventsCh <- client.RoundEventChannel{Err: err}
				return
			}

			ev, err := event{resp}.toRoundEvent()
			if err != nil {
				eventsCh <- client.RoundEventChannel{Err: err}
				return
			}

			eventsCh <- client.RoundEventChannel{Event: ev}
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

func (a *grpcClient) SubmitOffchainTx(
	ctx context.Context, virtualTx string, checkpointsTxs []string,
) ([]string, string, string, error) {
	req := &arkv1.SubmitOffchainTxRequest{
		VirtualTx:     virtualTx,
		CheckpointTxs: checkpointsTxs,
	}

	resp, err := a.svc.SubmitOffchainTx(ctx, req)
	if err != nil {
		return nil, "", "", err
	}

	return resp.GetSignedCheckpointTxs(), resp.GetSignedVirtualTx(), resp.GetTxid(), nil
}

func (a *grpcClient) FinalizeOffchainTx(
	ctx context.Context, virtualTxid string, checkpointsTxs []string,
) error {
	req := &arkv1.FinalizeOffchainTxRequest{
		Txid:          virtualTxid,
		CheckpointTxs: checkpointsTxs,
	}

	_, err := a.svc.FinalizeOffchainTx(ctx, req)
	return err
}

func (a *grpcClient) GetRound(
	ctx context.Context, txID string,
) (*client.Round, error) {
	req := &arkv1.GetRoundRequest{Txid: txID}
	resp, err := a.svc.GetRound(ctx, req)
	if err != nil {
		return nil, err
	}
	round := resp.GetRound()
	startedAt := time.Unix(round.GetStart(), 0)
	var endedAt *time.Time
	if round.GetEnd() > 0 {
		t := time.Unix(round.GetEnd(), 0)
		endedAt = &t
	}
	return &client.Round{
		ID:         round.GetId(),
		StartedAt:  &startedAt,
		EndedAt:    endedAt,
		Tx:         round.GetRoundTx(),
		Tree:       treeFromProto{round.GetVtxoTree()}.parse(),
		ForfeitTxs: round.GetForfeitTxs(),
		Connectors: treeFromProto{round.GetConnectors()}.parse(),
		Stage:      client.RoundStage(int(round.GetStage())),
	}, nil
}

func (a *grpcClient) GetRoundByID(
	ctx context.Context, roundID string,
) (*client.Round, error) {
	req := &arkv1.GetRoundByIdRequest{Id: roundID}
	resp, err := a.svc.GetRoundById(ctx, req)
	if err != nil {
		return nil, err
	}
	round := resp.GetRound()
	startedAt := time.Unix(round.GetStart(), 0)
	var endedAt *time.Time
	if round.GetEnd() > 0 {
		t := time.Unix(round.GetEnd(), 0)
		endedAt = &t
	}
	tree := treeFromProto{round.GetVtxoTree()}.parse()
	return &client.Round{
		ID:         round.GetId(),
		StartedAt:  &startedAt,
		EndedAt:    endedAt,
		Tx:         round.GetRoundTx(),
		Tree:       tree,
		ForfeitTxs: round.GetForfeitTxs(),
		Connectors: treeFromProto{round.GetConnectors()}.parse(),
		Stage:      client.RoundStage(int(round.GetStage())),
	}, nil
}

func (a *grpcClient) ListVtxos(
	ctx context.Context, addr string,
) ([]client.Vtxo, []client.Vtxo, error) {
	resp, err := a.svc.ListVtxos(ctx, &arkv1.ListVtxosRequest{Address: addr})
	if err != nil {
		return nil, nil, err
	}
	return vtxos(resp.GetSpendableVtxos()).toVtxos(), vtxos(resp.GetSpentVtxos()).toVtxos(), nil
}

func (c *grpcClient) Close() {
	//nolint:all
	c.conn.Close()
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
			case *arkv1.GetTransactionsStreamResponse_Round:
				eventsCh <- client.TransactionEvent{
					Round: &client.RoundTransaction{
						Txid:                 tx.Round.Txid,
						SpentVtxos:           vtxos(tx.Round.SpentVtxos).toVtxos(),
						SpendableVtxos:       vtxos(tx.Round.SpendableVtxos).toVtxos(),
						ClaimedBoardingUtxos: outpointsFromProto(tx.Round.ClaimedBoardingUtxos),
						Hex:                  tx.Round.GetHex(),
					},
				}
			case *arkv1.GetTransactionsStreamResponse_Redeem:
				eventsCh <- client.TransactionEvent{
					Redeem: &client.RedeemTransaction{
						Txid:           tx.Redeem.Txid,
						SpentVtxos:     vtxos(tx.Redeem.SpentVtxos).toVtxos(),
						SpendableVtxos: vtxos(tx.Redeem.SpendableVtxos).toVtxos(),
						Hex:            tx.Redeem.GetHex(),
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

func (c *grpcClient) SubscribeForAddress(
	ctx context.Context, addr string,
) (<-chan client.AddressEvent, func(), error) {
	ctx, cancel := context.WithCancel(ctx)

	stream, err := c.svc.SubscribeForAddress(ctx, &arkv1.SubscribeForAddressRequest{
		Address: addr,
	})
	if err != nil {
		cancel()
		return nil, nil, err
	}

	eventsCh := make(chan client.AddressEvent)

	go func() {
		defer close(eventsCh)

		for {
			resp, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					eventsCh <- client.AddressEvent{Err: client.ErrConnectionClosedByServer}
					return
				}
				if st, ok := status.FromError(err); ok && st.Code() == codes.Canceled {
					return
				}
				eventsCh <- client.AddressEvent{Err: err}
				return
			}

			eventsCh <- client.AddressEvent{
				NewVtxos:   vtxos(resp.NewVtxos).toVtxos(),
				SpentVtxos: vtxos(resp.SpentVtxos).toVtxos(),
			}
		}
	}()

	closeFn := func() {
		if err := stream.CloseSend(); err != nil {
			logrus.Warnf("failed to close address stream: %v", err)
		}
		cancel()
	}

	return eventsCh, closeFn, nil
}

func outpointsFromProto(protoOutpoints []*arkv1.Outpoint) []client.Outpoint {
	outpoints := make([]client.Outpoint, len(protoOutpoints))
	for i, o := range protoOutpoints {
		outpoints[i] = client.Outpoint{
			Txid: o.Txid,
			VOut: o.Vout,
		}
	}
	return outpoints
}
