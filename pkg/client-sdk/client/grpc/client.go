package grpcclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type grpcClient struct {
	conn      *grpc.ClientConn
	svc       arkv1.ArkServiceClient
	eventsCh  chan client.RoundEventChannel
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
	eventsCh := make(chan client.RoundEventChannel)
	treeCache := utils.NewCache[tree.CongestionTree]()

	return &grpcClient{conn, svc, eventsCh, treeCache}, nil
}

func (c *grpcClient) Close() {
	//nolint:all
	c.conn.Close()
}

func (a *grpcClient) GetEventStream(
	ctx context.Context, paymentID string,
) (<-chan client.RoundEventChannel, error) {
	req := &arkv1.GetEventStreamRequest{}
	stream, err := a.svc.GetEventStream(ctx, req)
	if err != nil {
		return nil, err
	}

	go func() {
		defer close(a.eventsCh)

		for {
			resp, err := stream.Recv()
			if err != nil {
				a.eventsCh <- client.RoundEventChannel{Err: err}
				return
			}

			a.eventsCh <- client.RoundEventChannel{Event: event{resp}.toRoundEvent()}
		}
	}()

	return a.eventsCh, nil
}

func (a *grpcClient) GetInfo(ctx context.Context) (*client.Info, error) {
	req := &arkv1.GetInfoRequest{}
	resp, err := a.svc.GetInfo(ctx, req)
	if err != nil {
		return nil, err
	}
	return &client.Info{
		Pubkey:              resp.GetPubkey(),
		RoundLifetime:       resp.GetRoundLifetime(),
		UnilateralExitDelay: resp.GetUnilateralExitDelay(),
		RoundInterval:       resp.GetRoundInterval(),
		Network:             resp.GetNetwork(),
		MinRelayFee:         resp.GetMinRelayFee(),
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
		Tx:         round.GetPoolTx(),
		Tree:       treeFromProto{round.GetCongestionTree()}.parse(),
		ForfeitTxs: round.GetForfeitTxs(),
		Connectors: round.GetConnectors(),
		Stage:      client.RoundStage(int(round.GetStage())),
	}, nil
}

func (a *grpcClient) Onboard(
	ctx context.Context, tx, userPubkey string, congestionTree tree.CongestionTree,
) error {
	req := &arkv1.OnboardRequest{
		BoardingTx:     tx,
		UserPubkey:     userPubkey,
		CongestionTree: treeToProto(congestionTree).parse(),
	}
	_, err := a.svc.Onboard(ctx, req)
	return err
}

func (a *grpcClient) RegisterPayment(
	ctx context.Context, inputs []client.VtxoKey,
) (string, error) {
	req := &arkv1.RegisterPaymentRequest{
		Inputs: ins(inputs).toProto(),
	}
	resp, err := a.svc.RegisterPayment(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.GetId(), nil
}

func (a *grpcClient) ClaimPayment(
	ctx context.Context, paymentID string, outputs []client.Output,
) error {
	req := &arkv1.ClaimPaymentRequest{
		Id:      paymentID,
		Outputs: outs(outputs).toProto(),
	}
	_, err := a.svc.ClaimPayment(ctx, req)
	return err
}

func (a *grpcClient) Ping(
	ctx context.Context, paymentID string,
) (*client.RoundFinalizationEvent, error) {
	req := &arkv1.PingRequest{
		PaymentId: paymentID,
	}
	resp, err := a.svc.Ping(ctx, req)
	if err != nil {
		return nil, err
	}
	event := resp.GetEvent()
	return &client.RoundFinalizationEvent{
		ID:         event.GetId(),
		Tx:         event.GetPoolTx(),
		ForfeitTxs: event.GetForfeitTxs(),
		Tree:       treeFromProto{event.GetCongestionTree()}.parse(),
		Connectors: event.GetConnectors(),
	}, nil
}

func (a *grpcClient) FinalizePayment(
	ctx context.Context, signedForfeitTxs []string,
) error {
	req := &arkv1.FinalizePaymentRequest{
		SignedForfeitTxs: signedForfeitTxs,
	}
	_, err := a.svc.FinalizePayment(ctx, req)
	return err
}

func (a *grpcClient) CreatePayment(
	ctx context.Context, inputs []client.VtxoKey, outputs []client.Output,
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
		Tx:         round.GetPoolTx(),
		Tree:       tree,
		ForfeitTxs: round.GetForfeitTxs(),
		Connectors: round.GetConnectors(),
		Stage:      client.RoundStage(int(round.GetStage())),
	}, nil
}

type out client.Output

func (o out) toProto() *arkv1.Output {
	return &arkv1.Output{
		Address: o.Address,
		Amount:  o.Amount,
	}
}

type outs []client.Output

func (o outs) toProto() []*arkv1.Output {
	list := make([]*arkv1.Output, 0, len(o))
	for _, oo := range o {
		list = append(list, out(oo).toProto())
	}
	return list
}

type event struct {
	*arkv1.GetEventStreamResponse
}

func (e event) toRoundEvent() client.RoundEvent {
	if ee := e.GetRoundFailed(); ee != nil {
		return client.RoundFailedEvent{
			ID:     ee.GetId(),
			Reason: ee.GetReason(),
		}
	}
	if ee := e.GetRoundFinalization(); ee != nil {
		tree := treeFromProto{ee.GetCongestionTree()}.parse()
		return client.RoundFinalizationEvent{
			ID:         ee.GetId(),
			Tx:         ee.GetPoolTx(),
			ForfeitTxs: ee.GetForfeitTxs(),
			Tree:       tree,
			Connectors: ee.GetConnectors(),
		}
	}
	ee := e.GetRoundFinalized()
	return client.RoundFinalizedEvent{
		ID:   ee.GetId(),
		Txid: ee.GetPoolTxid(),
	}
}

type vtxo struct {
	*arkv1.Vtxo
}

func (v vtxo) toVtxo() client.Vtxo {
	var expiresAt *time.Time
	if v.GetExpireAt() > 0 {
		t := time.Unix(v.GetExpireAt(), 0)
		expiresAt = &t
	}
	var redeemTx string
	var uncondForfeitTxs []string
	if v.GetPendingData() != nil {
		redeemTx = v.GetPendingData().GetRedeemTx()
		uncondForfeitTxs = v.GetPendingData().GetUnconditionalForfeitTxs()
	}
	return client.Vtxo{
		VtxoKey: client.VtxoKey{
			Txid: v.GetOutpoint().GetTxid(),
			VOut: v.GetOutpoint().GetVout(),
		},
		Amount:                  v.GetReceiver().GetAmount(),
		RoundTxid:               v.GetPoolTxid(),
		ExpiresAt:               expiresAt,
		Pending:                 v.GetPending(),
		RedeemTx:                redeemTx,
		UnconditionalForfeitTxs: uncondForfeitTxs,
	}
}

type vtxos []*arkv1.Vtxo

func (v vtxos) toVtxos() []client.Vtxo {
	list := make([]client.Vtxo, 0, len(v))
	for _, vv := range v {
		list = append(list, vtxo{vv}.toVtxo())
	}
	return list
}

type input client.VtxoKey

func (i input) toProto() *arkv1.Input {
	return &arkv1.Input{
		Txid: i.Txid,
		Vout: i.VOut,
	}
}

type ins []client.VtxoKey

func (i ins) toProto() []*arkv1.Input {
	list := make([]*arkv1.Input, 0, len(i))
	for _, ii := range i {
		list = append(list, input(ii).toProto())
	}
	return list
}

type treeFromProto struct {
	*arkv1.Tree
}

func (t treeFromProto) parse() tree.CongestionTree {
	levels := make(tree.CongestionTree, 0, len(t.GetLevels()))

	for _, level := range t.GetLevels() {
		nodes := make([]tree.Node, 0, len(level.Nodes))

		for _, node := range level.Nodes {
			nodes = append(nodes, tree.Node{
				Txid:       node.Txid,
				Tx:         node.Tx,
				ParentTxid: node.ParentTxid,
			})
		}

		levels = append(levels, nodes)
	}

	for j, treeLvl := range levels {
		for i, node := range treeLvl {
			if len(levels.Children(node.Txid)) == 0 {
				levels[j][i] = tree.Node{
					Txid:       node.Txid,
					Tx:         node.Tx,
					ParentTxid: node.ParentTxid,
					Leaf:       true,
				}
			}
		}
	}

	return levels
}

type treeToProto tree.CongestionTree

func (t treeToProto) parse() *arkv1.Tree {
	levels := make([]*arkv1.TreeLevel, 0, len(t))
	for _, level := range t {
		levelProto := &arkv1.TreeLevel{
			Nodes: make([]*arkv1.Node, 0, len(level)),
		}

		for _, node := range level {
			levelProto.Nodes = append(levelProto.Nodes, &arkv1.Node{
				Txid:       node.Txid,
				Tx:         node.Tx,
				ParentTxid: node.ParentTxid,
			})
		}

		levels = append(levels, levelProto)
	}
	return &arkv1.Tree{
		Levels: levels,
	}
}
