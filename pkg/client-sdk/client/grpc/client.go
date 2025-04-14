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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type service struct {
	arkv1.ArkServiceClient
	arkv1.ExplorerServiceClient
	arkv1.IndexerServiceClient
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

	svc := service{arkv1.NewArkServiceClient(conn), arkv1.NewExplorerServiceClient(conn), arkv1.NewIndexerServiceClient(conn)}
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
		PubKey:                     resp.GetPubkey(),
		VtxoTreeExpiry:             resp.GetVtxoTreeExpiry(),
		UnilateralExitDelay:        resp.GetUnilateralExitDelay(),
		RoundInterval:              resp.GetRoundInterval(),
		Network:                    resp.GetNetwork(),
		Dust:                       uint64(resp.GetDust()),
		BoardingDescriptorTemplate: resp.GetBoardingDescriptorTemplate(),
		ForfeitAddress:             resp.GetForfeitAddress(),
		Version:                    resp.GetVersion(),
		MarketHourStartTime:        resp.GetMarketHour().GetNextStartTime(),
		MarketHourEndTime:          resp.GetMarketHour().GetNextEndTime(),
		MarketHourPeriod:           resp.GetMarketHour().GetPeriod(),
		MarketHourRoundInterval:    resp.GetMarketHour().GetRoundInterval(),
		UtxoMinAmount:              resp.GetUtxoMinAmount(),
		UtxoMaxAmount:              resp.GetUtxoMaxAmount(),
		VtxoMinAmount:              resp.GetVtxoMinAmount(),
		VtxoMaxAmount:              resp.GetVtxoMaxAmount(),
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

// IndexerService methods implementation

func (a *grpcClient) GetCommitmentTx(ctx context.Context, txid string) (*client.CommitmentTxInfo, error) {
	req := &arkv1.GetCommitmentTxRequest{
		Txid: txid,
	}
	resp, err := a.svc.IndexerServiceClient.GetCommitmentTx(ctx, req)
	if err != nil {
		return nil, err
	}

	batches := make(map[uint32]*client.Batch)
	for vout, batch := range resp.GetBatches() {
		batches[vout] = &client.Batch{
			TotalBatchAmount:   batch.GetTotalBatchAmount(),
			TotalForfeitAmount: batch.GetTotalForfeitAmount(),
			TotalInputVtxos:    batch.GetTotalInputVtxos(),
			TotalOutputVtxos:   batch.GetTotalOutputVtxos(),
			ExpiresAt:          batch.GetExpiresAt(),
			Swept:              batch.GetSwept(),
		}
	}

	return &client.CommitmentTxInfo{
		StartedAt: resp.GetStartedAt(),
		EndedAt:   resp.GetEndedAt(),
		Batches:   batches,
	}, nil
}

func (a *grpcClient) GetVtxoTree(ctx context.Context, batchOutpoint client.Outpoint, page client.PageRequest) (*client.VtxoTreeResponse, error) {
	req := &arkv1.GetVtxoTreeRequest{
		BatchOutpoint: &arkv1.IndexerOutpoint{
			Txid: batchOutpoint.Txid,
			Vout: batchOutpoint.VOut,
		},
		Page: &arkv1.IndexerPageRequest{
			Size:  page.Size,
			Index: page.Index,
		},
	}

	resp, err := a.svc.IndexerServiceClient.GetVtxoTree(ctx, req)
	if err != nil {
		return nil, err
	}

	nodes := make([]client.IndexerNode, 0, len(resp.GetVtxoTree()))
	for _, node := range resp.GetVtxoTree() {
		nodes = append(nodes, client.IndexerNode{
			Txid:       node.GetTxid(),
			Tx:         node.GetTx(),
			ParentTxid: node.GetParentTxid(),
			Level:      node.GetLevel(),
			LevelIndex: node.GetLevelIndex(),
		})
	}

	return &client.VtxoTreeResponse{
		VtxoTree: nodes,
		Page: client.PageResponse{
			Current: resp.GetPage().GetCurrent(),
			Next:    resp.GetPage().GetNext(),
			Total:   resp.GetPage().GetTotal(),
		},
	}, nil
}

func (a *grpcClient) GetForfeitTxs(ctx context.Context, batchOutpoint client.Outpoint, page client.PageRequest) (*client.ForfeitTxsResponse, error) {
	req := &arkv1.GetForfeitTxsRequest{
		BatchOutpoint: &arkv1.IndexerOutpoint{
			Txid: batchOutpoint.Txid,
			Vout: batchOutpoint.VOut,
		},
		Page: &arkv1.IndexerPageRequest{
			Size:  page.Size,
			Index: page.Index,
		},
	}

	resp, err := a.svc.IndexerServiceClient.GetForfeitTxs(ctx, req)
	if err != nil {
		return nil, err
	}

	return &client.ForfeitTxsResponse{
		Txs: resp.GetTxs(),
		Page: client.PageResponse{
			Current: resp.GetPage().GetCurrent(),
			Next:    resp.GetPage().GetNext(),
			Total:   resp.GetPage().GetTotal(),
		},
	}, nil
}

func (a *grpcClient) GetConnectors(ctx context.Context, batchOutpoint client.Outpoint, page client.PageRequest) (*client.ConnectorsResponse, error) {
	req := &arkv1.GetConnectorsRequest{
		BatchOutpoint: &arkv1.IndexerOutpoint{
			Txid: batchOutpoint.Txid,
			Vout: batchOutpoint.VOut,
		},
		Page: &arkv1.IndexerPageRequest{
			Size:  page.Size,
			Index: page.Index,
		},
	}

	resp, err := a.svc.IndexerServiceClient.GetConnectors(ctx, req)
	if err != nil {
		return nil, err
	}

	connectors := make([]client.IndexerNode, 0, len(resp.GetConnectors()))
	for _, connector := range resp.GetConnectors() {
		connectors = append(connectors, client.IndexerNode{
			Txid:       connector.GetTxid(),
			Tx:         connector.GetTx(),
			ParentTxid: connector.GetParentTxid(),
			Level:      connector.GetLevel(),
			LevelIndex: connector.GetLevelIndex(),
		})
	}

	return &client.ConnectorsResponse{
		Connectors: connectors,
		Page: client.PageResponse{
			Current: resp.GetPage().GetCurrent(),
			Next:    resp.GetPage().GetNext(),
			Total:   resp.GetPage().GetTotal(),
		},
	}, nil
}

func (a *grpcClient) GetSpendableVtxos(ctx context.Context, address string, page client.PageRequest) (*client.SpendableVtxosResponse, error) {
	req := &arkv1.GetSpendableVtxosRequest{
		Address: address,
		Page: &arkv1.IndexerPageRequest{
			Size:  page.Size,
			Index: page.Index,
		},
	}

	resp, err := a.svc.IndexerServiceClient.GetSpendableVtxos(ctx, req)
	if err != nil {
		return nil, err
	}

	vtxos := make([]client.IndexerVtxo, 0, len(resp.GetVtxos()))
	for _, vtxo := range resp.GetVtxos() {
		vtxos = append(vtxos, client.IndexerVtxo{
			Outpoint: client.Outpoint{
				Txid: vtxo.GetOutpoint().GetTxid(),
				VOut: vtxo.GetOutpoint().GetVout(),
			},
			CreatedAt: vtxo.GetCreatedAt(),
			ExpiresAt: vtxo.GetExpiresAt(),
			Amount:    vtxo.GetAmount(),
			Script:    vtxo.GetScript(),
			IsLeaf:    vtxo.GetIsLeaf(),
			IsSwept:   vtxo.GetIsSwept(),
			IsSpent:   vtxo.GetIsSpent(),
			SpentBy:   vtxo.GetSpentBy(),
		})
	}

	return &client.SpendableVtxosResponse{
		Vtxos: vtxos,
		Page: client.PageResponse{
			Current: resp.GetPage().GetCurrent(),
			Next:    resp.GetPage().GetNext(),
			Total:   resp.GetPage().GetTotal(),
		},
	}, nil
}

func (a *grpcClient) GetTransactionHistory(ctx context.Context, address string, startTime, endTime int64, page client.PageRequest) (*client.TransactionHistoryResponse, error) {
	req := &arkv1.GetTransactionHistoryRequest{
		Address:   address,
		StartTime: startTime,
		EndTime:   endTime,
		Page: &arkv1.IndexerPageRequest{
			Size:  page.Size,
			Index: page.Index,
		},
	}

	resp, err := a.svc.IndexerServiceClient.GetTransactionHistory(ctx, req)
	if err != nil {
		return nil, err
	}

	history := make([]client.TxHistoryRecord, 0, len(resp.GetHistory()))
	for _, record := range resp.GetHistory() {
		history = append(history, client.TxHistoryRecord{
			Txid:        getTxidFromHistoryRecord(record),
			Type:        client.TxType(record.GetType()),
			Amount:      record.GetAmount(),
			CreatedAt:   record.GetCreatedAt(),
			ConfirmedAt: record.GetConfirmedAt(),
			IsSettled:   record.GetIsSettled(),
		})
	}

	return &client.TransactionHistoryResponse{
		History: history,
		Page: client.PageResponse{
			Current: resp.GetPage().GetCurrent(),
			Next:    resp.GetPage().GetNext(),
			Total:   resp.GetPage().GetTotal(),
		},
	}, nil
}

func getTxidFromHistoryRecord(record *arkv1.IndexerTxHistoryRecord) string {
	switch {
	case record.GetBoardingTxid() != "":
		return record.GetBoardingTxid()
	case record.GetCommitmentTxid() != "":
		return record.GetCommitmentTxid()
	case record.GetSweepTxid() != "":
		return record.GetSweepTxid()
	case record.GetArkTxid() != "":
		return record.GetArkTxid()
	default:
		return ""
	}
}

func (a *grpcClient) GetVtxoChain(ctx context.Context, outpoint client.Outpoint, page client.PageRequest) (*client.VtxoChainResponse, error) {
	req := &arkv1.GetVtxoChainRequest{
		Outpoint: &arkv1.IndexerOutpoint{
			Txid: outpoint.Txid,
			Vout: outpoint.VOut,
		},
		Page: &arkv1.IndexerPageRequest{
			Size:  page.Size,
			Index: page.Index,
		},
	}

	resp, err := a.svc.IndexerServiceClient.GetVtxoChain(ctx, req)
	if err != nil {
		return nil, err
	}

	graph := make(map[string]*client.Transactions)
	for txid, txs := range resp.GetGraph() {
		graph[txid] = &client.Transactions{
			Txs: txs.GetTxs(),
		}
	}

	return &client.VtxoChainResponse{
		Graph: graph,
		Page: client.PageResponse{
			Current: resp.GetPage().GetCurrent(),
			Next:    resp.GetPage().GetNext(),
			Total:   resp.GetPage().GetTotal(),
		},
	}, nil
}

func (a *grpcClient) GetVirtualTxs(ctx context.Context, txids []string, page client.PageRequest) (*client.VirtualTxsResponse, error) {
	req := &arkv1.GetVirtualTxsRequest{
		Txids: txids,
		Page: &arkv1.IndexerPageRequest{
			Size:  page.Size,
			Index: page.Index,
		},
	}

	resp, err := a.svc.IndexerServiceClient.GetVirtualTxs(ctx, req)
	if err != nil {
		return nil, err
	}

	return &client.VirtualTxsResponse{
		Txs: resp.GetTxs(),
		Page: client.PageResponse{
			Current: resp.GetPage().GetCurrent(),
			Next:    resp.GetPage().GetNext(),
			Total:   resp.GetPage().GetTotal(),
		},
	}, nil
}

func (a *grpcClient) GetSweptCommitmentTx(ctx context.Context, txid string) (*client.SweptCommitmentTxResponse, error) {
	req := &arkv1.GetSweptCommitmentTxRequest{
		Txid: txid,
	}

	resp, err := a.svc.IndexerServiceClient.GetSweptCommitmentTx(ctx, req)
	if err != nil {
		return nil, err
	}

	return &client.SweptCommitmentTxResponse{
		SweptBy: resp.GetSweptBy(),
	}, nil
}
