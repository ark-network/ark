package arksdk

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"time"

	arkgrpcclient "github.com/ark-network/ark-sdk/grpc"
	"github.com/ark-network/ark-sdk/rest/service/arkservicerestclient"
	"github.com/ark-network/ark-sdk/rest/service/arkservicerestclient/ark_service"
	"github.com/ark-network/ark-sdk/rest/service/models"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/tree"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/vulpemventures/go-elements/psetv2"
)

type arkTransportClient interface {
	getInfo(ctx context.Context) (*arkv1.GetInfoResponse, error)
	listVtxos(ctx context.Context, addr string) (*arkv1.ListVtxosResponse, error)
	getSpendableVtxos(
		ctx context.Context, addr string, computeExpiryDetails bool,
	) ([]vtxo, error)
	getRound(ctx context.Context, txID string) (*arkv1.GetRoundResponse, error)
	getRoundByID(ctx context.Context, roundID string) (*arkv1.GetRoundByIdResponse, error)
	getRedeemBranches(
		ctx context.Context,
		explorer Explorer,
		vtxos []vtxo,
	) (map[string]*redeemBranch, error)
	getOffchainBalance(
		ctx context.Context, addr string, computeExpiration bool,
	) (uint64, map[int64]uint64, error)
	onboard(
		ctx context.Context, req *arkv1.OnboardRequest,
	) (*arkv1.OnboardResponse, error)
	registerPayment(
		ctx context.Context, req *arkv1.RegisterPaymentRequest,
	) (*arkv1.RegisterPaymentResponse, error)
	claimPayment(
		ctx context.Context, req *arkv1.ClaimPaymentRequest,
	) (*arkv1.ClaimPaymentResponse, error)
	getEventStream(
		ctx context.Context, paymentID string, req *arkv1.GetEventStreamRequest,
	) (*EventStream, error)
	ping(ctx context.Context, req *arkv1.PingRequest) (*arkv1.PingResponse, error)
	finalizePayment(
		ctx context.Context, req *arkv1.FinalizePaymentRequest,
	) (*arkv1.FinalizePaymentResponse, error)
	setExplorerSvc(explorerSvc Explorer)
}

func newArkTransportClient(
	aspUrl string, protocol TransportProtocol, explorer Explorer,
) (arkTransportClient, error) {
	switch protocol {
	case Grpc:
		grpcClient, closeFn, err := newGrpcClient(aspUrl)
		if err != nil {
			return nil, err
		}

		return &arkInnerClient{
			grpcClient:  grpcClient,
			grpcCloseFn: closeFn,
			explorerSvc: explorer,
			eventStream: &EventStream{
				eventResp: make(chan *arkv1.GetEventStreamResponse),
				err:       make(chan error),
			},
		}, nil
	case Rest:
		resClient, err := newRestClient(aspUrl)
		if err != nil {
			return nil, err
		}

		return &arkInnerClient{
			resClient:   resClient,
			explorerSvc: explorer,
			eventStream: &EventStream{
				eventResp: make(chan *arkv1.GetEventStreamResponse),
				err:       make(chan error),
			},
		}, nil
	default:
		return nil, errors.New("unknown protocol")
	}
}

type arkInnerClient struct {
	grpcClient  arkgrpcclient.ArkGrpcClient
	grpcCloseFn func()

	resClient *arkservicerestclient.ArkV1ServiceProto

	explorerSvc Explorer

	eventStream *EventStream
}

func (a *arkInnerClient) setExplorerSvc(explorerSvc Explorer) {
	a.explorerSvc = explorerSvc
}

type EventStream struct {
	eventResp chan *arkv1.GetEventStreamResponse
	err       chan error
}

func (a *arkInnerClient) getEventStream(
	ctx context.Context, paymentID string, req *arkv1.GetEventStreamRequest,
) (*EventStream, error) {
	switch {
	case a.grpcClient != nil:
		stream, err := a.grpcClient.Service().GetEventStream(ctx, req)
		if err != nil {
			return nil, err
		}

		go func() {
			defer close(a.eventStream.eventResp)
			defer close(a.eventStream.err)

			for {
				resp, err := stream.Recv()
				if err != nil {
					a.eventStream.err <- err
					return
				}

				a.eventStream.eventResp <- resp
			}
		}()
	case a.resClient != nil:
		go func(payID string) {
			defer close(a.eventStream.eventResp)
			defer close(a.eventStream.err)

			timeout := time.After(30 * time.Second) // TODO make this configurable

		mainloop:
			for {
				select {
				case <-timeout:
					a.eventStream.err <- errors.New("timeout reached")
					break mainloop
				default:
					resp, err := a.ping(ctx, &arkv1.PingRequest{
						PaymentId: payID,
					})
					if err != nil {
						a.eventStream.err <- err
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
						a.eventStream.eventResp <- &arkv1.GetEventStreamResponse{
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
						}

						for {
							roundID := resp.GetEvent().GetId()
							round, err := a.getRoundByID(ctx, roundID)
							if err != nil {
								a.eventStream.err <- err
							}

							if round.GetRound().GetStage() == arkv1.RoundStage_ROUND_STAGE_FINALIZED {
								ptx, _ := psetv2.NewPsetFromBase64(round.GetRound().GetPoolTx())
								utx, _ := ptx.UnsignedTx()
								a.eventStream.eventResp <- &arkv1.GetEventStreamResponse{
									Event: &arkv1.GetEventStreamResponse_RoundFinalized{
										RoundFinalized: &arkv1.RoundFinalizedEvent{
											PoolTxid: utx.TxHash().String(),
										},
									},
								}

								break mainloop
							}

							if round.GetRound().GetStage() == arkv1.RoundStage_ROUND_STAGE_FAILED {
								a.eventStream.eventResp <- &arkv1.GetEventStreamResponse{
									Event: &arkv1.GetEventStreamResponse_RoundFailed{
										RoundFailed: &arkv1.RoundFailed{
											Id:     round.GetRound().GetId(),
											Reason: "unknown reason", //TODO getRoundByID should return the reason
										},
									},
								}

								break mainloop
							}

							time.Sleep(1 * time.Second)
						}
					}

					time.Sleep(1 * time.Second)
				}
			}
		}(paymentID)
	}

	return a.eventStream, nil
}

func (a *arkInnerClient) getInfo(ctx context.Context) (*arkv1.GetInfoResponse, error) {
	switch {
	case a.grpcClient != nil:
		return a.grpcClient.Service().GetInfo(ctx, &arkv1.GetInfoRequest{})
	case a.resClient != nil:
		resp, err := a.resClient.ArkService.ArkServiceGetInfo(ark_service.NewArkServiceGetInfoParams())
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

	return nil, nil
}

func (a *arkInnerClient) listVtxos(
	ctx context.Context,
	addr string,
) (*arkv1.ListVtxosResponse, error) {
	switch {
	case a.grpcClient != nil:
		return a.grpcClient.Service().ListVtxos(
			ctx, &arkv1.ListVtxosRequest{
				Address: addr,
			},
		)
	case a.resClient != nil:
		resp, err := a.resClient.ArkService.ArkServiceListVtxos(
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

	return nil, nil
}

func (a *arkInnerClient) getRound(
	ctx context.Context, txID string,
) (*arkv1.GetRoundResponse, error) {
	switch {
	case a.grpcClient != nil:
		return a.grpcClient.Service().GetRound(
			ctx, &arkv1.GetRoundRequest{
				Txid: txID,
			},
		)
	case a.resClient != nil:
		resp, err := a.resClient.ArkService.ArkServiceGetRound(
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

	return nil, nil
}

func (a *arkInnerClient) getSpendableVtxos(
	ctx context.Context, addr string, computeExpiryDetails bool,
) ([]vtxo, error) {
	allVtxos, err := a.listVtxos(ctx, addr)
	if err != nil {
		return nil, err
	}

	vtxos := make([]vtxo, 0, len(allVtxos.GetSpendableVtxos()))
	for _, v := range allVtxos.GetSpendableVtxos() {
		var expireAt *time.Time
		if v.ExpireAt > 0 {
			t := time.Unix(v.ExpireAt, 0)
			expireAt = &t
		}
		if v.Swept {
			continue
		}
		vtxos = append(vtxos, vtxo{
			amount:   v.Receiver.Amount,
			txid:     v.Outpoint.Txid,
			vout:     v.Outpoint.Vout,
			poolTxid: v.PoolTxid,
			expireAt: expireAt,
		})
	}

	if !computeExpiryDetails {
		return vtxos, nil
	}

	redeemBranches, err := a.getRedeemBranches(ctx, a.explorerSvc, vtxos)
	if err != nil {
		return nil, err
	}

	for vtxoTxid, branch := range redeemBranches {
		expiration, err := branch.expireAt(a.explorerSvc)
		if err != nil {
			return nil, err
		}

		for i, vtxo := range vtxos {
			if vtxo.txid == vtxoTxid {
				vtxos[i].expireAt = expiration
				break
			}
		}
	}

	return vtxos, nil
}

type vtxo struct {
	amount   uint64
	txid     string
	vout     uint32
	poolTxid string
	expireAt *time.Time
}

func newGrpcClient(
	aspUrl string,
) (arkgrpcclient.ArkGrpcClient, func(), error) {
	return arkgrpcclient.New(aspUrl)
}

func newRestClient(
	serviceURL string,
) (*arkservicerestclient.ArkV1ServiceProto, error) {
	parsedURL, err := url.Parse(serviceURL)
	if err != nil {
		return nil, err
	}

	schemes := []string{parsedURL.Scheme}
	host := parsedURL.Host
	basePath := parsedURL.Path

	if basePath == "" {
		basePath = arkservicerestclient.DefaultBasePath
	}

	cfg := &arkservicerestclient.TransportConfig{
		Host:     host,
		BasePath: basePath,
		Schemes:  schemes,
	}

	transport := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	return arkservicerestclient.New(transport, strfmt.Default), nil
}

func (a *arkInnerClient) getRedeemBranches(
	ctx context.Context,
	explorer Explorer,
	vtxos []vtxo,
) (map[string]*redeemBranch, error) {
	congestionTrees := make(map[string]tree.CongestionTree, 0)
	redeemBranches := make(map[string]*redeemBranch, 0)

	for _, vtxo := range vtxos {
		if _, ok := congestionTrees[vtxo.poolTxid]; !ok {
			round, err := a.getRound(ctx, vtxo.poolTxid)
			if err != nil {
				return nil, err
			}

			treeFromRound := round.GetRound().GetCongestionTree()
			congestionTree, err := toCongestionTree(treeFromRound)
			if err != nil {
				return nil, err
			}

			congestionTrees[vtxo.poolTxid] = congestionTree
		}

		redeemBranch, err := newRedeemBranch(
			explorer, congestionTrees[vtxo.poolTxid], vtxo,
		)
		if err != nil {
			return nil, err
		}

		redeemBranches[vtxo.txid] = redeemBranch
	}

	return redeemBranches, nil
}

func (a *arkInnerClient) getOffchainBalance(
	ctx context.Context, addr string, computeExpiration bool,
) (uint64, map[int64]uint64, error) {
	amountByExpiration := make(map[int64]uint64, 0)

	vtxos, err := a.getSpendableVtxos(ctx, addr, computeExpiration)
	if err != nil {
		return 0, nil, err
	}
	var balance uint64
	for _, vtxo := range vtxos {
		balance += vtxo.amount

		if vtxo.expireAt != nil {
			expiration := vtxo.expireAt.Unix()

			if _, ok := amountByExpiration[expiration]; !ok {
				amountByExpiration[expiration] = 0
			}

			amountByExpiration[expiration] += vtxo.amount
		}
	}

	return balance, amountByExpiration, nil
}

func (a *arkInnerClient) onboard(
	ctx context.Context, req *arkv1.OnboardRequest,
) (*arkv1.OnboardResponse, error) {
	switch {
	case a.grpcClient != nil:
		return a.grpcClient.Service().Onboard(ctx, req)
	case a.resClient != nil:
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
		_, err := a.resClient.ArkService.ArkServiceOnboard(
			ark_service.NewArkServiceOnboardParams().WithBody(&body),
		)
		if err != nil {
			return nil, err
		}

		return &arkv1.OnboardResponse{}, nil
	}

	return nil, nil
}

func (a *arkInnerClient) registerPayment(
	ctx context.Context, req *arkv1.RegisterPaymentRequest,
) (*arkv1.RegisterPaymentResponse, error) {
	switch {
	case a.grpcClient != nil:
		return a.grpcClient.Service().RegisterPayment(ctx, req)
	case a.resClient != nil:
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
		resp, err := a.resClient.ArkService.ArkServiceRegisterPayment(
			ark_service.NewArkServiceRegisterPaymentParams().WithBody(&body),
		)
		if err != nil {
			return nil, err
		}

		return &arkv1.RegisterPaymentResponse{
			Id: resp.Payload.ID,
		}, nil
	}

	return nil, nil
}

func (a *arkInnerClient) claimPayment(
	ctx context.Context, req *arkv1.ClaimPaymentRequest,
) (*arkv1.ClaimPaymentResponse, error) {
	switch {
	case a.grpcClient != nil:
		return a.grpcClient.Service().ClaimPayment(ctx, req)
	case a.resClient != nil:
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

		_, err := a.resClient.ArkService.ArkServiceClaimPayment(
			ark_service.NewArkServiceClaimPaymentParams().WithBody(&body),
		)
		if err != nil {
			return nil, err
		}

		return &arkv1.ClaimPaymentResponse{}, nil
	}

	return nil, nil
}

func (a *arkInnerClient) ping(
	ctx context.Context, req *arkv1.PingRequest,
) (*arkv1.PingResponse, error) {
	switch {
	case a.grpcClient != nil:
		return a.grpcClient.Service().Ping(ctx, req)
	case a.resClient != nil:
		r := ark_service.NewArkServicePingParams()
		r.SetPaymentID(req.GetPaymentId())
		resp, err := a.resClient.ArkService.ArkServicePing(r)
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

	return nil, nil
}

func (a *arkInnerClient) finalizePayment(
	ctx context.Context, req *arkv1.FinalizePaymentRequest,
) (*arkv1.FinalizePaymentResponse, error) {
	switch {
	case a.grpcClient != nil:
		return a.grpcClient.Service().FinalizePayment(ctx, req)
	case a.resClient != nil:
		body := models.V1FinalizePaymentRequest{
			SignedForfeitTxs: req.GetSignedForfeitTxs(),
		}
		_, err := a.resClient.ArkService.ArkServiceFinalizePayment(
			ark_service.NewArkServiceFinalizePaymentParams().WithBody(&body),
		)
		if err != nil {
			return nil, err
		}

		return &arkv1.FinalizePaymentResponse{}, nil
	}

	return nil, nil
}

func (a *arkInnerClient) getRoundByID(
	ctx context.Context, roundID string,
) (*arkv1.GetRoundByIdResponse, error) {
	switch {
	case a.grpcClient != nil:
		return a.grpcClient.Service().GetRoundById(ctx, &arkv1.GetRoundByIdRequest{
			Id: roundID,
		})
	case a.resClient != nil:
		resp, err := a.resClient.ArkService.ArkServiceGetRoundByID(
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

		stage := stageStrToInt(resp.Payload.Round.Stage)

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

	return nil, nil
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
