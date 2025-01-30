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
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type service struct {
	arkv1.ArkServiceClient
	arkv1.ExplorerServiceClient
}

type grpcClient struct {
	conn      *grpc.ClientConn
	svc       service
	treeCache *utils.Cache[tree.VtxoTree]
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
	treeCache := utils.NewCache[tree.VtxoTree]()

	return &grpcClient{conn, svc, treeCache}, nil
}

func (a *grpcClient) GetInfo(ctx context.Context) (*client.Info, error) {
	req := &arkv1.GetInfoRequest{}
	resp, err := a.svc.GetInfo(ctx, req)
	if err != nil {
		return nil, err
	}
	return &client.Info{
		PubKey:                     resp.GetPubkey(),
		VtxoTreeExpiry:             resp.GetVtxoTreeExpiry(),
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

func (a *grpcClient) RegisterNotesForNextRound(
	ctx context.Context, notes []string,
) (string, error) {
	req := &arkv1.RegisterInputsForNextRoundRequest{
		Notes: notes,
	}
	resp, err := a.svc.RegisterInputsForNextRound(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.GetRequestId(), nil
}

func (a *grpcClient) RegisterOutputsForNextRound(
	ctx context.Context, requestID string, outputs []client.Output, musig2 *tree.Musig2,
) error {
	req := &arkv1.RegisterOutputsForNextRoundRequest{
		RequestId: requestID,
		Outputs:   outs(outputs).toProto(),
	}
	if musig2 != nil {
		req.Musig2 = &arkv1.Musig2{
			CosignersPublicKeys: musig2.CosignersPublicKeys,
			SigningAll:          musig2.SigningType == tree.SignAll,
		}
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
		Pubkey:     cosignerPubkey,
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

func (a *grpcClient) GetEventStream(
	ctx context.Context, requestID string,
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
	ctx context.Context, requestID string,
) error {
	req := &arkv1.PingRequest{
		RequestId: requestID,
	}
	_, err := a.svc.Ping(ctx, req)
	return err
}

func (a *grpcClient) SubmitRedeemTx(
	ctx context.Context, redeemTx string,
) (string, string, error) {
	req := &arkv1.SubmitRedeemTxRequest{
		RedeemTx: redeemTx,
	}

	resp, err := a.svc.SubmitRedeemTx(ctx, req)
	if err != nil {
		return "", "", err
	}

	return resp.GetSignedRedeemTx(), resp.GetTxid(), nil
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
	tree := treeFromProto{round.GetVtxoTree()}.parse()
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

func (c *grpcClient) GetTransactionsStream(
	ctx context.Context,
) (<-chan client.TransactionEvent, func(), error) {
	stream, err := c.svc.GetTransactionsStream(ctx, &arkv1.GetTransactionsStreamRequest{})
	if err != nil {
		return nil, nil, err
	}

	eventCh := make(chan client.TransactionEvent)

	go func() {
		defer close(eventCh)
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				eventCh <- client.TransactionEvent{Err: err}
				return
			}

			switch tx := resp.Tx.(type) {
			case *arkv1.GetTransactionsStreamResponse_Round:
				eventCh <- client.TransactionEvent{
					Round: &client.RoundTransaction{
						Txid:                 tx.Round.Txid,
						SpentVtxos:           outpointsFromProto(tx.Round.SpentVtxos),
						SpendableVtxos:       vtxos(tx.Round.SpendableVtxos).toVtxos(),
						ClaimedBoardingUtxos: outpointsFromProto(tx.Round.ClaimedBoardingUtxos),
					},
				}
			case *arkv1.GetTransactionsStreamResponse_Redeem:
				eventCh <- client.TransactionEvent{
					Redeem: &client.RedeemTransaction{
						Txid:           tx.Redeem.Txid,
						SpentVtxos:     outpointsFromProto(tx.Redeem.SpentVtxos),
						SpendableVtxos: vtxos(tx.Redeem.SpendableVtxos).toVtxos(),
					},
				}
			}
		}
	}()

	closeFn := func() {
		if err := stream.CloseSend(); err != nil {
			logrus.Warnf("failed to close stream: %v", err)
		}
	}

	return eventCh, closeFn, nil
}

func (a *grpcClient) SetNostrRecipient(
	ctx context.Context, nostrRecipient string, vtxos []client.SignedVtxoOutpoint,
) error {
	req := &arkv1.SetNostrRecipientRequest{
		NostrRecipient: nostrRecipient,
		Vtxos:          signedVtxosToProto(vtxos),
	}
	_, err := a.svc.SetNostrRecipient(ctx, req)
	return err
}

func (a *grpcClient) DeleteNostrRecipient(
	ctx context.Context, vtxos []client.SignedVtxoOutpoint,
) error {
	req := &arkv1.DeleteNostrRecipientRequest{
		Vtxos: signedVtxosToProto(vtxos),
	}
	_, err := a.svc.DeleteNostrRecipient(ctx, req)
	return err
}

func signedVtxosToProto(vtxos []client.SignedVtxoOutpoint) []*arkv1.SignedVtxoOutpoint {
	protoVtxos := make([]*arkv1.SignedVtxoOutpoint, len(vtxos))
	for i, v := range vtxos {
		protoVtxos[i] = &arkv1.SignedVtxoOutpoint{
			Outpoint: &arkv1.Outpoint{
				Txid: v.Outpoint.Txid,
				Vout: uint32(v.Outpoint.VOut),
			},
			Proof: &arkv1.OwnershipProof{
				ControlBlock: v.Proof.ControlBlock,
				Script:       v.Proof.Script,
				Signature:    v.Proof.Signature,
			},
		}
	}
	return protoVtxos
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
