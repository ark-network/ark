package restclient

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/ark-network/ark-sdk/client"
	"github.com/ark-network/ark-sdk/client/rest/service/arkservice"
	"github.com/ark-network/ark-sdk/client/rest/service/arkservice/ark_service"
	"github.com/ark-network/ark-sdk/client/rest/service/models"
	"github.com/ark-network/ark-sdk/explorer"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/tree"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/vulpemventures/go-elements/psetv2"
)

type restClient struct {
	svc            ark_service.ClientService
	eventsCh       chan client.RoundEventChannel
	requestTimeout time.Duration
}

func NewClient(args ...interface{}) (client.Client, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("invalid number of args")
	}
	aspUrl, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid asp url")
	}

	svc, err := newRestClient(aspUrl)
	if err != nil {
		return nil, err
	}
	eventsCh := make(chan client.RoundEventChannel, 0)
	reqTimeout := 15 * time.Second

	return &restClient{svc, eventsCh, reqTimeout}, nil
}

func (c *restClient) Close() {}

func (a *restClient) GetEventStream(
	ctx context.Context, paymentID string, req *arkv1.GetEventStreamRequest,
) (<-chan client.RoundEventChannel, error) {
	go func(payID string) {
		defer close(a.eventsCh)

		timeout := time.After(a.requestTimeout)

		for {
			select {
			case <-timeout:
				a.eventsCh <- client.RoundEventChannel{
					Err: fmt.Errorf("timeout reached"),
				}
				return
			default:
				resp, err := a.Ping(ctx, &arkv1.PingRequest{
					PaymentId: payID,
				})
				if err != nil {
					a.eventsCh <- client.RoundEventChannel{
						Err: err,
					}
					return
				}

				if resp.GetEvent() != nil {
					levels := make([]*arkv1.TreeLevel, 0, len(resp.GetEvent().GetCongestionTree().GetLevels()))
					for _, l := range resp.GetEvent().GetCongestionTree().GetLevels() {
						nodes := make([]*arkv1.Node, 0, len(l.Nodes))
						for _, n := range l.Nodes {
							nodes = append(nodes, &arkv1.Node{
								Txid:       n.Txid,
								Tx:         n.Tx,
								ParentTxid: n.ParentTxid,
							})
						}
						levels = append(levels, &arkv1.TreeLevel{
							Nodes: nodes,
						})
					}
					a.eventsCh <- client.RoundEventChannel{
						Event: &arkv1.GetEventStreamResponse{
							Event: &arkv1.GetEventStreamResponse_RoundFinalization{
								RoundFinalization: &arkv1.RoundFinalizationEvent{
									Id:         resp.GetEvent().GetId(),
									PoolTx:     resp.GetEvent().GetPoolTx(),
									ForfeitTxs: resp.GetEvent().GetForfeitTxs(),
									CongestionTree: &arkv1.Tree{
										Levels: levels,
									},
									Connectors: resp.GetEvent().GetConnectors(),
								},
							},
						},
					}

					for {
						roundID := resp.GetEvent().GetId()
						round, err := a.GetRoundByID(ctx, roundID)
						if err != nil {
							a.eventsCh <- client.RoundEventChannel{
								Err: err,
							}
							return
						}

						if round.GetRound().GetStage() == arkv1.RoundStage_ROUND_STAGE_FINALIZED {
							ptx, _ := psetv2.NewPsetFromBase64(round.GetRound().GetPoolTx())
							utx, _ := ptx.UnsignedTx()
							a.eventsCh <- client.RoundEventChannel{
								Event: &arkv1.GetEventStreamResponse{
									Event: &arkv1.GetEventStreamResponse_RoundFinalized{
										RoundFinalized: &arkv1.RoundFinalizedEvent{
											PoolTxid: utx.TxHash().String(),
										},
									},
								},
							}
							return
						}

						if round.GetRound().GetStage() == arkv1.RoundStage_ROUND_STAGE_FAILED {
							a.eventsCh <- client.RoundEventChannel{
								Event: &arkv1.GetEventStreamResponse{
									Event: &arkv1.GetEventStreamResponse_RoundFailed{
										RoundFailed: &arkv1.RoundFailed{
											Id: round.GetRound().GetId(),
										},
									},
								},
							}
							return
						}

						time.Sleep(1 * time.Second)
					}
				}

				time.Sleep(1 * time.Second)
			}
		}
	}(paymentID)

	return a.eventsCh, nil
}

func (a *restClient) GetInfo(
	ctx context.Context,
) (*arkv1.GetInfoResponse, error) {
	resp, err := a.svc.ArkServiceGetInfo(ark_service.NewArkServiceGetInfoParams())
	if err != nil {
		return nil, err
	}

	roundLifetime, err := strconv.Atoi(resp.Payload.RoundLifetime)
	if err != nil {
		return nil, err
	}

	unilateralExitDelay, err := strconv.Atoi(resp.Payload.UnilateralExitDelay)
	if err != nil {
		return nil, err
	}

	roundInterval, err := strconv.Atoi(resp.Payload.RoundInterval)
	if err != nil {
		return nil, err
	}

	minRelayFee, err := strconv.Atoi(resp.Payload.MinRelayFee)
	if err != nil {
		return nil, err
	}

	return &arkv1.GetInfoResponse{
		Pubkey:              resp.Payload.Pubkey,
		RoundLifetime:       int64(roundLifetime),
		UnilateralExitDelay: int64(unilateralExitDelay),
		RoundInterval:       int64(roundInterval),
		Network:             resp.Payload.Network,
		MinRelayFee:         int64(minRelayFee),
	}, nil
}

func (a *restClient) ListVtxos(
	ctx context.Context, addr string,
) (*arkv1.ListVtxosResponse, error) {
	resp, err := a.svc.ArkServiceListVtxos(
		ark_service.NewArkServiceListVtxosParams().WithAddress(addr),
	)
	if err != nil {
		return nil, err
	}

	vtxos := make([]*arkv1.Vtxo, 0, len(resp.Payload.SpendableVtxos))
	for _, v := range resp.Payload.SpendableVtxos {
		expAt, err := strconv.Atoi(v.ExpireAt)
		if err != nil {
			return nil, err
		}

		amount, err := strconv.Atoi(v.Receiver.Amount)
		if err != nil {
			return nil, err
		}

		vtxos = append(vtxos, &arkv1.Vtxo{
			Outpoint: &arkv1.Input{
				Txid: v.Outpoint.Txid,
				Vout: uint32(v.Outpoint.Vout),
			},
			Receiver: &arkv1.Output{
				Address: v.Receiver.Address,
				Amount:  uint64(amount),
			},
			Spent:    v.Spent,
			PoolTxid: v.PoolTxid,
			SpentBy:  v.SpentBy,
			ExpireAt: int64(expAt),
			Swept:    v.Swept,
		})
	}

	return &arkv1.ListVtxosResponse{
		SpendableVtxos: vtxos,
	}, nil
}

func (a *restClient) GetRound(
	ctx context.Context, txID string,
) (*arkv1.GetRoundResponse, error) {
	resp, err := a.svc.ArkServiceGetRound(
		ark_service.NewArkServiceGetRoundParams().WithTxid(txID),
	)
	if err != nil {
		return nil, err
	}

	start, err := strconv.Atoi(resp.Payload.Round.Start)
	if err != nil {
		return nil, err
	}

	end, err := strconv.Atoi(resp.Payload.Round.End)
	if err != nil {
		return nil, err
	}

	levels := make([]*arkv1.TreeLevel, 0, len(resp.Payload.Round.CongestionTree.Levels))
	for _, l := range resp.Payload.Round.CongestionTree.Levels {
		nodes := make([]*arkv1.Node, 0, len(l.Nodes))
		for _, n := range l.Nodes {
			nodes = append(nodes, &arkv1.Node{
				Txid:       n.Txid,
				Tx:         n.Tx,
				ParentTxid: n.ParentTxid,
			})
		}
		levels = append(levels, &arkv1.TreeLevel{
			Nodes: nodes,
		})
	}

	return &arkv1.GetRoundResponse{
		Round: &arkv1.Round{
			Id:     resp.Payload.Round.ID,
			Start:  int64(start),
			End:    int64(end),
			PoolTx: resp.Payload.Round.PoolTx,
			CongestionTree: &arkv1.Tree{
				Levels: levels,
			},
			ForfeitTxs: resp.Payload.Round.ForfeitTxs,
			Connectors: resp.Payload.Round.Connectors,
		},
	}, nil
}

func (a *restClient) GetSpendableVtxos(
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

func (a *restClient) GetRedeemBranches(
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

func (a *restClient) GetOffchainBalance(
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

func (a *restClient) Onboard(
	ctx context.Context, req *arkv1.OnboardRequest,
) (*arkv1.OnboardResponse, error) {
	levels := make([]*models.V1TreeLevel, 0, len(req.GetCongestionTree().GetLevels()))
	for _, l := range req.GetCongestionTree().GetLevels() {
		nodes := make([]*models.V1Node, 0, len(l.GetNodes()))
		for _, n := range l.GetNodes() {
			nodes = append(nodes, &models.V1Node{
				Txid:       n.GetTxid(),
				Tx:         n.GetTx(),
				ParentTxid: n.GetParentTxid(),
			})
		}
		levels = append(levels, &models.V1TreeLevel{
			Nodes: nodes,
		})
	}
	congestionTree := models.V1Tree{
		Levels: levels,
	}
	body := models.V1OnboardRequest{
		BoardingTx:     req.GetBoardingTx(),
		CongestionTree: &congestionTree,
		UserPubkey:     req.GetUserPubkey(),
	}
	_, err := a.svc.ArkServiceOnboard(
		ark_service.NewArkServiceOnboardParams().WithBody(&body),
	)
	if err != nil {
		return nil, err
	}

	return &arkv1.OnboardResponse{}, nil
}

func (a *restClient) RegisterPayment(
	ctx context.Context, req *arkv1.RegisterPaymentRequest,
) (*arkv1.RegisterPaymentResponse, error) {
	inputs := make([]*models.V1Input, 0, len(req.GetInputs()))
	for _, i := range req.GetInputs() {
		inputs = append(inputs, &models.V1Input{
			Txid: i.GetTxid(),
			Vout: int64(i.GetVout()),
		})
	}
	body := models.V1RegisterPaymentRequest{
		Inputs: inputs,
	}
	resp, err := a.svc.ArkServiceRegisterPayment(
		ark_service.NewArkServiceRegisterPaymentParams().WithBody(&body),
	)
	if err != nil {
		return nil, err
	}

	return &arkv1.RegisterPaymentResponse{
		Id: resp.Payload.ID,
	}, nil
}

func (a *restClient) ClaimPayment(
	ctx context.Context, req *arkv1.ClaimPaymentRequest,
) (*arkv1.ClaimPaymentResponse, error) {
	outputs := make([]*models.V1Output, 0, len(req.GetOutputs()))
	for _, o := range req.GetOutputs() {
		outputs = append(outputs, &models.V1Output{
			Address: o.GetAddress(),
			Amount:  strconv.Itoa(int(o.GetAmount())),
		})
	}
	body := models.V1ClaimPaymentRequest{
		ID:      req.GetId(),
		Outputs: outputs,
	}

	_, err := a.svc.ArkServiceClaimPayment(
		ark_service.NewArkServiceClaimPaymentParams().WithBody(&body),
	)
	if err != nil {
		return nil, err
	}

	return &arkv1.ClaimPaymentResponse{}, nil
}

func (a *restClient) Ping(
	ctx context.Context, req *arkv1.PingRequest,
) (*arkv1.PingResponse, error) {
	r := ark_service.NewArkServicePingParams()
	r.SetPaymentID(req.GetPaymentId())
	resp, err := a.svc.ArkServicePing(r)
	if err != nil {
		return nil, err
	}

	var event *arkv1.RoundFinalizationEvent
	if resp.Payload.Event != nil &&
		resp.Payload.Event.ID != "" &&
		len(resp.Payload.Event.ForfeitTxs) > 0 &&
		len(resp.Payload.Event.CongestionTree.Levels) > 0 &&
		len(resp.Payload.Event.Connectors) > 0 &&
		resp.Payload.Event.PoolTx != "" {
		levels := make([]*arkv1.TreeLevel, 0, len(resp.Payload.Event.CongestionTree.Levels))
		for _, l := range resp.Payload.Event.CongestionTree.Levels {
			nodes := make([]*arkv1.Node, 0, len(l.Nodes))
			for _, n := range l.Nodes {
				nodes = append(nodes, &arkv1.Node{
					Txid:       n.Txid,
					Tx:         n.Tx,
					ParentTxid: n.ParentTxid,
				})
			}
			levels = append(levels, &arkv1.TreeLevel{
				Nodes: nodes,
			})
		}

		event = &arkv1.RoundFinalizationEvent{
			Id:         resp.Payload.Event.ID,
			PoolTx:     resp.Payload.Event.PoolTx,
			ForfeitTxs: resp.Payload.Event.ForfeitTxs,
			CongestionTree: &arkv1.Tree{
				Levels: levels,
			},
			Connectors: resp.Payload.Event.Connectors,
		}
	}

	return &arkv1.PingResponse{
		ForfeitTxs: resp.Payload.ForfeitTxs,
		Event:      event,
	}, nil
}

func (a *restClient) FinalizePayment(
	ctx context.Context, req *arkv1.FinalizePaymentRequest,
) (*arkv1.FinalizePaymentResponse, error) {
	body := models.V1FinalizePaymentRequest{
		SignedForfeitTxs: req.GetSignedForfeitTxs(),
	}
	_, err := a.svc.ArkServiceFinalizePayment(
		ark_service.NewArkServiceFinalizePaymentParams().WithBody(&body),
	)
	if err != nil {
		return nil, err
	}

	return &arkv1.FinalizePaymentResponse{}, nil
}

func (a *restClient) GetRoundByID(
	ctx context.Context, roundID string,
) (*arkv1.GetRoundByIdResponse, error) {
	resp, err := a.svc.ArkServiceGetRoundByID(
		ark_service.NewArkServiceGetRoundByIDParams().WithID(roundID),
	)
	if err != nil {
		return nil, err
	}

	start, err := strconv.Atoi(resp.Payload.Round.Start)
	if err != nil {
		return nil, err
	}

	end, err := strconv.Atoi(resp.Payload.Round.End)
	if err != nil {
		return nil, err
	}

	levels := make([]*arkv1.TreeLevel, 0, len(resp.Payload.Round.CongestionTree.Levels))
	for _, l := range resp.Payload.Round.CongestionTree.Levels {
		nodes := make([]*arkv1.Node, 0, len(l.Nodes))
		for _, n := range l.Nodes {
			nodes = append(nodes, &arkv1.Node{
				Txid:       n.Txid,
				Tx:         n.Tx,
				ParentTxid: n.ParentTxid,
			})
		}
		levels = append(levels, &arkv1.TreeLevel{
			Nodes: nodes,
		})
	}

	stage := stageStrToInt(*resp.Payload.Round.Stage)

	return &arkv1.GetRoundByIdResponse{
		Round: &arkv1.Round{
			Id:     resp.Payload.Round.ID,
			Start:  int64(start),
			End:    int64(end),
			PoolTx: resp.Payload.Round.PoolTx,
			CongestionTree: &arkv1.Tree{
				Levels: levels,
			},
			ForfeitTxs: resp.Payload.Round.ForfeitTxs,
			Connectors: resp.Payload.Round.Connectors,
			Stage:      arkv1.RoundStage(stage),
		},
	}, nil
}

func newRestClient(
	serviceURL string,
) (ark_service.ClientService, error) {
	parsedURL, err := url.Parse(serviceURL)
	if err != nil {
		return nil, err
	}

	schemes := []string{parsedURL.Scheme}
	host := parsedURL.Host
	basePath := parsedURL.Path

	if basePath == "" {
		basePath = arkservice.DefaultBasePath
	}

	cfg := &arkservice.TransportConfig{
		Host:     host,
		BasePath: basePath,
		Schemes:  schemes,
	}

	transport := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	svc := arkservice.New(transport, strfmt.Default)
	return svc.ArkService, nil
}

func stageStrToInt(stage models.V1RoundStage) int {
	switch stage {
	case models.V1RoundStageROUNDSTAGEUNSPECIFIED:
		return 0
	case models.V1RoundStageROUNDSTAGEREGISTRATION:
		return 1
	case models.V1RoundStageROUNDSTAGEFINALIZATION:
		return 2
	case models.V1RoundStageROUNDSTAGEFINALIZED:
		return 3
	case models.V1RoundStageROUNDSTAGEFAILED:
		return 4
	}

	return -1
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
