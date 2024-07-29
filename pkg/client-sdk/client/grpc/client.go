package grpcclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ark-network/ark-sdk/client"
	"github.com/ark-network/ark-sdk/explorer"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/tree"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type grpcClient struct {
	conn     *grpc.ClientConn
	svc      arkv1.ArkServiceClient
	eventsCh chan client.RoundEventChannel
}

func NewClient(aspUrl string) (client.Client, error) {
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

	return &grpcClient{conn, svc, eventsCh}, nil
}

func (c *grpcClient) Close() {
	//nolint:all
	c.conn.Close()
}

func (a *grpcClient) GetEventStream(
	ctx context.Context, paymentID string, req *arkv1.GetEventStreamRequest,
) (<-chan client.RoundEventChannel, error) {
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

			a.eventsCh <- client.RoundEventChannel{Event: resp}
		}
	}()

	return a.eventsCh, nil
}

func (a *grpcClient) GetInfo(ctx context.Context) (*arkv1.GetInfoResponse, error) {
	return a.svc.GetInfo(ctx, &arkv1.GetInfoRequest{})
}

func (a *grpcClient) ListVtxos(
	ctx context.Context,
	addr string,
) (*arkv1.ListVtxosResponse, error) {
	return a.svc.ListVtxos(ctx, &arkv1.ListVtxosRequest{Address: addr})
}

func (a *grpcClient) GetRound(
	ctx context.Context, txID string,
) (*arkv1.GetRoundResponse, error) {
	return a.svc.GetRound(ctx, &arkv1.GetRoundRequest{Txid: txID})
}

func (a *grpcClient) GetSpendableVtxos(
	ctx context.Context, addr string, explorerSvc explorer.Explorer,
) ([]*client.Vtxo, error) {
	allVtxos, err := a.ListVtxos(ctx, addr)
	if err != nil {
		return nil, err
	}

	vtxos := make([]*client.Vtxo, 0, len(allVtxos.GetSpendableVtxos()))
	for _, v := range allVtxos.GetSpendableVtxos() {
		var expireAt *time.Time
		if v.ExpireAt > 0 {
			t := time.Unix(v.ExpireAt, 0)
			expireAt = &t
		}
		if v.Swept {
			continue
		}
		vtxos = append(vtxos, &client.Vtxo{
			Amount:    v.Receiver.Amount,
			Txid:      v.Outpoint.Txid,
			VOut:      v.Outpoint.Vout,
			RoundTxid: v.PoolTxid,
			ExpiresAt: expireAt,
		})
	}

	if explorerSvc == nil {
		return vtxos, nil
	}

	redeemBranches, err := a.GetRedeemBranches(ctx, vtxos, explorerSvc)
	if err != nil {
		return nil, err
	}

	for vtxoTxid, branch := range redeemBranches {
		expiration, err := branch.ExpiresAt()
		if err != nil {
			return nil, err
		}

		for i, vtxo := range vtxos {
			if vtxo.Txid == vtxoTxid {
				vtxos[i].ExpiresAt = expiration
				break
			}
		}
	}

	return vtxos, nil
}

func (a *grpcClient) GetRedeemBranches(
	ctx context.Context, vtxos []*client.Vtxo, explorerSvc explorer.Explorer,
) (map[string]*client.RedeemBranch, error) {
	congestionTrees := make(map[string]tree.CongestionTree, 0)
	redeemBranches := make(map[string]*client.RedeemBranch, 0)

	for _, vtxo := range vtxos {
		if _, ok := congestionTrees[vtxo.RoundTxid]; !ok {
			round, err := a.GetRound(ctx, vtxo.RoundTxid)
			if err != nil {
				return nil, err
			}

			treeFromRound := round.GetRound().GetCongestionTree()
			congestionTree, err := toCongestionTree(treeFromRound)
			if err != nil {
				return nil, err
			}

			congestionTrees[vtxo.RoundTxid] = congestionTree
		}

		redeemBranch, err := client.NewRedeemBranch(
			explorerSvc, congestionTrees[vtxo.RoundTxid], vtxo,
		)
		if err != nil {
			return nil, err
		}

		redeemBranches[vtxo.Txid] = redeemBranch
	}

	return redeemBranches, nil
}

func (a *grpcClient) GetOffchainBalance(
	ctx context.Context, addr string, explorerSvc explorer.Explorer,
) (uint64, map[int64]uint64, error) {
	amountByExpiration := make(map[int64]uint64, 0)

	vtxos, err := a.GetSpendableVtxos(ctx, addr, explorerSvc)
	if err != nil {
		return 0, nil, err
	}
	var balance uint64
	for _, vtxo := range vtxos {
		balance += vtxo.Amount

		if vtxo.ExpiresAt != nil {
			expiration := vtxo.ExpiresAt.Unix()

			if _, ok := amountByExpiration[expiration]; !ok {
				amountByExpiration[expiration] = 0
			}

			amountByExpiration[expiration] += vtxo.Amount
		}
	}

	return balance, amountByExpiration, nil
}

func (a *grpcClient) Onboard(
	ctx context.Context, req *arkv1.OnboardRequest,
) (*arkv1.OnboardResponse, error) {
	return a.svc.Onboard(ctx, req)
}

func (a *grpcClient) RegisterPayment(
	ctx context.Context, req *arkv1.RegisterPaymentRequest,
) (*arkv1.RegisterPaymentResponse, error) {
	return a.svc.RegisterPayment(ctx, req)
}

func (a *grpcClient) ClaimPayment(
	ctx context.Context, req *arkv1.ClaimPaymentRequest,
) (*arkv1.ClaimPaymentResponse, error) {
	return a.svc.ClaimPayment(ctx, req)
}

func (a *grpcClient) Ping(
	ctx context.Context, req *arkv1.PingRequest,
) (*arkv1.PingResponse, error) {
	return a.svc.Ping(ctx, req)
}

func (a *grpcClient) FinalizePayment(
	ctx context.Context, req *arkv1.FinalizePaymentRequest,
) (*arkv1.FinalizePaymentResponse, error) {
	return a.svc.FinalizePayment(ctx, req)
}

func (a *grpcClient) GetRoundByID(
	ctx context.Context, roundID string,
) (*arkv1.GetRoundByIdResponse, error) {
	return a.svc.GetRoundById(ctx, &arkv1.GetRoundByIdRequest{
		Id: roundID,
	})
}

func toCongestionTree(treeFromProto *arkv1.Tree) (tree.CongestionTree, error) {
	levels := make(tree.CongestionTree, 0, len(treeFromProto.Levels))

	for _, level := range treeFromProto.Levels {
		nodes := make([]tree.Node, 0, len(level.Nodes))

		for _, node := range level.Nodes {
			nodes = append(nodes, tree.Node{
				Txid:       node.Txid,
				Tx:         node.Tx,
				ParentTxid: node.ParentTxid,
				Leaf:       false,
			})
		}

		levels = append(levels, nodes)
	}

	for j, treeLvl := range levels {
		for i, node := range treeLvl {
			if len(levels.Children(node.Txid)) == 0 {
				levels[j][i].Leaf = true
			}
		}
	}

	return levels, nil
}
