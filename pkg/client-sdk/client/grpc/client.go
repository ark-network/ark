package grpcclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type grpcClient struct {
	conn      *grpc.ClientConn
	svc       arkv1.ArkServiceClient
	treeCache *utils.Cache[tree.CongestionTree]
}

func NewClient(aspUrl string) (client.ASPClient, error) {
	if len(aspUrl) <= 0 {
		return nil, fmt.Errorf("missing asp url")
	}

	creds := insecure.NewCredentials()
	port := 80
	if strings.HasPrefix(aspUrl, "https://") {
		aspUrl = strings.TrimPrefix(aspUrl, "https://")
		creds = credentials.NewTLS(nil)
		port = 443
	}
	if !strings.Contains(aspUrl, ":") {
		aspUrl = fmt.Sprintf("%s:%d", aspUrl, port)
	}
	conn, err := grpc.NewClient(aspUrl, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}

	svc := arkv1.NewArkServiceClient(conn)
	treeCache := utils.NewCache[tree.CongestionTree]()

	return &grpcClient{conn, svc, treeCache}, nil
}

func (a *grpcClient) GetInfo(ctx context.Context) (*client.Info, error) {
	req := &arkv1.GetInfoRequest{}
	resp, err := a.svc.GetInfo(ctx, req)
	if err != nil {
		return nil, err
	}
	return &client.Info{
		Pubkey:                     resp.GetPubkey(),
		RoundLifetime:              resp.GetRoundLifetime(),
		UnilateralExitDelay:        resp.GetUnilateralExitDelay(),
		RoundInterval:              resp.GetRoundInterval(),
		Network:                    resp.GetNetwork(),
		Dust:                       uint64(resp.GetDust()),
		BoardingDescriptorTemplate: resp.GetBoardingDescriptorTemplate(),
		ForfeitAddress:             resp.GetForfeitAddress(),
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
	ctx context.Context, inputs []client.Input, ephemeralPublicKey string,
) (string, error) {
	req := &arkv1.RegisterInputsForNextRoundRequest{
		Inputs: ins(inputs).toProto(),
	}
	if len(ephemeralPublicKey) > 0 {
		req.EphemeralPubkey = &ephemeralPublicKey
	}

	resp, err := a.svc.RegisterInputsForNextRound(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.GetId(), nil
}

func (a *grpcClient) RegisterOutputsForNextRound(
	ctx context.Context, paymentID string, outputs []client.Output,
) error {
	req := &arkv1.RegisterOutputsForNextRoundRequest{
		Id:      paymentID,
		Outputs: outs(outputs).toProto(),
	}
	_, err := a.svc.RegisterOutputsForNextRound(ctx, req)
	return err
}

func (a *grpcClient) SubmitTreeNonces(
	ctx context.Context, roundID, cosignerPubkey string, nonces bitcointree.TreeNonces,
) error {
	var nonceBuffer bytes.Buffer

	if err := nonces.Encode(&nonceBuffer); err != nil {
		return err
	}

	serializedNonces := hex.EncodeToString(nonceBuffer.Bytes())

	req := &arkv1.SubmitTreeNoncesRequest{
		RoundId:    roundID,
		PublicKey:  cosignerPubkey,
		TreeNonces: serializedNonces,
	}

	if _, err := a.svc.SubmitTreeNonces(ctx, req); err != nil {
		return err
	}

	return nil
}

func (a *grpcClient) SubmitTreeSignatures(
	ctx context.Context, roundID, cosignerPubkey string, signatures bitcointree.TreePartialSigs,
) error {
	var sigsBuffer bytes.Buffer

	if err := signatures.Encode(&sigsBuffer); err != nil {
		return err
	}

	serializedSigs := hex.EncodeToString(sigsBuffer.Bytes())

	req := &arkv1.SubmitTreeSignaturesRequest{
		RoundId:        roundID,
		PublicKey:      cosignerPubkey,
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

func (a *grpcClient) GetEventStream(
	ctx context.Context, paymentID string,
) (<-chan client.RoundEventChannel, func(), error) {
	req := &arkv1.GetEventStreamRequest{}
	stream, err := a.svc.GetEventStream(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	eventsCh := make(chan client.RoundEventChannel)

	go func() {
		defer close(eventsCh)

		for {
			select {
			case <-stream.Context().Done():
				return
			default:
				resp, err := stream.Recv()
				if err != nil {
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
		}
	}()

	closeFn := func() {
		if err := stream.CloseSend(); err != nil {
			logrus.Warnf("failed to close stream: %v", err)
		}
	}

	return eventsCh, closeFn, nil
}

func (a *grpcClient) Ping(
	ctx context.Context, paymentID string,
) (client.RoundEvent, error) {
	req := &arkv1.PingRequest{
		PaymentId: paymentID,
	}
	resp, err := a.svc.Ping(ctx, req)
	if err != nil {
		return nil, err
	}

	if resp.GetEvent() == nil {
		return nil, nil
	}

	return event{resp}.toRoundEvent()
}

func (a *grpcClient) CreatePayment(
	ctx context.Context, inputs []client.Input, outputs []client.Output,
) (string, []string, error) {
	req := &arkv1.CreatePaymentRequest{
		Inputs:  ins(inputs).toProto(),
		Outputs: outs(outputs).toProto(),
	}
	resp, err := a.svc.CreatePayment(ctx, req)
	if err != nil {
		return "", nil, err
	}
	return resp.SignedRedeemTx, resp.UsignedUnconditionalForfeitTxs, nil
}

func (a *grpcClient) CompletePayment(
	ctx context.Context, redeemTx string, signedForfeitTxs []string,
) error {
	req := &arkv1.CompletePaymentRequest{
		SignedRedeemTx:                redeemTx,
		SignedUnconditionalForfeitTxs: signedForfeitTxs,
	}
	_, err := a.svc.CompletePayment(ctx, req)
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
		Tree:       treeFromProto{round.GetCongestionTree()}.parse(),
		ForfeitTxs: round.GetForfeitTxs(),
		Connectors: round.GetConnectors(),
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
	tree := treeFromProto{round.GetCongestionTree()}.parse()
	return &client.Round{
		ID:         round.GetId(),
		StartedAt:  &startedAt,
		EndedAt:    endedAt,
		Tx:         round.GetRoundTx(),
		Tree:       tree,
		ForfeitTxs: round.GetForfeitTxs(),
		Connectors: round.GetConnectors(),
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
