package handlers

import (
	"context"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/server/internal/core/application"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type indexerService struct {
	indexerSvc application.IndexerService
}

func NewIndexerService(indexerSvc application.IndexerService) arkv1.IndexerServiceServer {
	return indexerService{
		indexerSvc: indexerSvc,
	}
}

func (e indexerService) GetCommitmentTx(
	ctx context.Context, request *arkv1.GetCommitmentTxRequest,
) (*arkv1.GetCommitmentTxResponse, error) {
	resp, err := e.indexerSvc.GetCommitmentTxInfo(ctx, request.Txid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get commitment tx info: %v", err)
	}

	batches := make(map[uint32]*arkv1.IndexerBatch)
	for vout, batch := range resp.Batches {
		batches[uint32(vout)] = &arkv1.IndexerBatch{
			TotalBatchAmount:   batch.TotalBatchAmount,
			TotalForfeitAmount: batch.TotalForfeitAmount,
			TotalInputVtxos:    batch.TotalInputVtxos,
			TotalOutputVtxos:   batch.TotalOutputVtxos,
			ExpiresAt:          batch.ExpiresAt,
			Swept:              batch.Swept,
		}
	}

	return &arkv1.GetCommitmentTxResponse{
		StartedAt: resp.StartedAt,
		EndedAt:   resp.EndAt,
		Batches:   batches,
	}, nil
}

func (e indexerService) GetVtxoTree(ctx context.Context, request *arkv1.GetVtxoTreeRequest) (*arkv1.GetVtxoTreeResponse, error) {
	req := application.VtxoTreeReq{
		BatchOutpoint: application.Outpoint{
			Txid: request.BatchOutpoint.Txid,
			Vout: request.BatchOutpoint.Vout,
		},
		Page: application.PageReq{
			PageSize: int(request.Page.Size),
			PageNum:  int(request.Page.Index),
		},
	}

	resp, err := e.indexerSvc.GetVtxoTree(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get vtxo tree: %v", err)
	}

	nodes := make([]*arkv1.IndexerNode, len(resp.Nodes))
	for i, node := range resp.Nodes {
		nodes[i] = &arkv1.IndexerNode{
			Txid:       node.Txid,
			Tx:         node.Tx,
			ParentTxid: node.ParentTxid,
			Level:      node.Level,
			LevelIndex: node.LevelIndex,
		}
	}

	return &arkv1.GetVtxoTreeResponse{
		VtxoTree: nodes,
		Page: &arkv1.IndexerPageResponse{
			Current: int32(resp.Page.Current),
			Next:    int32(resp.Page.Next),
			Total:   int32(resp.Page.Total),
		},
	}, nil
}

func (e indexerService) GetForfeitTxs(ctx context.Context, request *arkv1.GetForfeitTxsRequest) (*arkv1.GetForfeitTxsResponse, error) {
	req := application.ForfeitTxsReq{
		BatchOutpoint: application.Outpoint{
			Txid: request.BatchOutpoint.Txid,
			Vout: request.BatchOutpoint.Vout,
		},
		Page: application.PageReq{
			PageSize: int(request.Page.Size),
			PageNum:  int(request.Page.Index),
		},
	}

	resp, err := e.indexerSvc.GetForfeitTxs(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get forfeit txs: %v", err)
	}

	return &arkv1.GetForfeitTxsResponse{
		Txs: resp.Txs,
		Page: &arkv1.IndexerPageResponse{
			Current: int32(resp.Page.Current),
			Next:    int32(resp.Page.Next),
			Total:   int32(resp.Page.Total),
		},
	}, nil
}

func (e indexerService) GetConnectors(ctx context.Context, request *arkv1.GetConnectorsRequest) (*arkv1.GetConnectorsResponse, error) {
	req := application.ConnectorsReq{
		BatchOutpoint: application.Outpoint{
			Txid: request.BatchOutpoint.Txid,
			Vout: request.BatchOutpoint.Vout,
		},
		Page: application.PageReq{
			PageSize: int(request.Page.Size),
			PageNum:  int(request.Page.Index),
		},
	}

	resp, err := e.indexerSvc.GetConnectors(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get connectors: %v", err)
	}

	connectors := make([]*arkv1.IndexerNode, len(resp.Connectors))
	for i, connector := range resp.Connectors {
		connectors[i] = &arkv1.IndexerNode{
			Txid:       connector.Txid,
			Tx:         connector.Tx,
			ParentTxid: connector.ParentTxid,
			Level:      connector.Level,
			LevelIndex: connector.LevelIndex,
		}
	}

	return &arkv1.GetConnectorsResponse{
		Connectors: connectors,
		Page: &arkv1.IndexerPageResponse{
			Current: int32(resp.Page.Current),
			Next:    int32(resp.Page.Next),
			Total:   int32(resp.Page.Total),
		},
	}, nil
}

func (e indexerService) GetSpendableVtxos(ctx context.Context, request *arkv1.GetSpendableVtxosRequest) (*arkv1.GetSpendableVtxosResponse, error) {
	req := application.SpendableVtxosReq{
		Address: request.Address,
		Page: application.PageReq{
			PageSize: int(request.Page.Size),
			PageNum:  int(request.Page.Index),
		},
	}

	resp, err := e.indexerSvc.GetSpendableVtxos(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get spendable vtxos: %v", err)
	}

	vtxos := make([]*arkv1.IndexerVtxo, len(resp.Vtxos))
	for i, vtxo := range resp.Vtxos {
		vtxos[i] = &arkv1.IndexerVtxo{
			Outpoint: &arkv1.IndexerOutpoint{
				Txid: vtxo.Txid,
				Vout: vtxo.VOut,
			},
			CreatedAt: vtxo.CreatedAt,
			ExpiresAt: vtxo.ExpireAt,
			Amount:    vtxo.Amount,
			Script:    vtxo.PubKey,
			IsLeaf:    vtxo.RoundTxid == "",
			IsSwept:   vtxo.Swept,
			IsSpent:   vtxo.Spent,
			SpentBy:   vtxo.SpentBy,
		}
	}

	return &arkv1.GetSpendableVtxosResponse{
		Vtxos: vtxos,
		Page: &arkv1.IndexerPageResponse{
			Current: int32(resp.Page.Current),
			Next:    int32(resp.Page.Next),
			Total:   int32(resp.Page.Total),
		},
	}, nil
}

func (e indexerService) GetTransactionHistory(ctx context.Context, request *arkv1.GetTransactionHistoryRequest) (*arkv1.GetTransactionHistoryResponse, error) {
	req := application.TxHistoryReq{
		Address:   request.Address,
		StartTime: request.StartTime,
		EndTime:   request.EndTime,
		Page: application.PageReq{
			PageSize: int(request.Page.Size),
			PageNum:  int(request.Page.Index),
		},
	}

	resp, err := e.indexerSvc.GetTransactionHistory(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get transaction history: %v", err)
	}

	history := make([]*arkv1.IndexerTxHistoryRecord, len(resp.Records))
	for i, record := range resp.Records {
		history[i] = &arkv1.IndexerTxHistoryRecord{
			Type:        arkv1.IndexerTxType(record.Type),
			Amount:      record.Amount,
			CreatedAt:   record.CreatedAt.Unix(),
			ConfirmedAt: record.ConfirmedAt,
			IsSettled:   record.Settled,
		}
	}

	return &arkv1.GetTransactionHistoryResponse{
		History: history,
		Page: &arkv1.IndexerPageResponse{
			Current: int32(resp.Pagination.Current),
			Next:    int32(resp.Pagination.Next),
			Total:   int32(resp.Pagination.Total),
		},
	}, nil
}

func (e indexerService) GetVtxoChain(ctx context.Context, request *arkv1.GetVtxoChainRequest) (*arkv1.GetVtxoChainResponse, error) {
	req := application.VtxoChainReq{
		VtxoKey: application.Outpoint{
			Txid: request.Outpoint.Txid,
			Vout: request.Outpoint.Vout,
		},
		Page: application.PageReq{
			PageSize: int(request.Page.Size),
			PageNum:  int(request.Page.Index),
		},
	}

	resp, err := e.indexerSvc.GetVtxoChain(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get vtxo chain: %v", err)
	}

	graph := make(map[string]*arkv1.IndexerTransactions)
	for key, value := range resp.Transactions {
		graph[key] = &arkv1.IndexerTransactions{
			Txs: value,
		}
	}

	return &arkv1.GetVtxoChainResponse{
		Graph: graph,
		Page: &arkv1.IndexerPageResponse{
			Current: int32(resp.Page.Current),
			Next:    int32(resp.Page.Next),
			Total:   int32(resp.Page.Total),
		},
	}, nil
}

func (e indexerService) GetVirtualTxs(ctx context.Context, request *arkv1.GetVirtualTxsRequest) (*arkv1.GetVirtualTxsResponse, error) {
	req := application.VirtualTxsReq{
		TxIDs: request.Txids,
		Page: application.PageReq{
			PageSize: int(request.Page.Size),
			PageNum:  int(request.Page.Index),
		},
	}

	resp, err := e.indexerSvc.GetVirtualTxs(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get virtual txs: %v", err)
	}

	return &arkv1.GetVirtualTxsResponse{
		Txs: resp.Transactions,
		Page: &arkv1.IndexerPageResponse{
			Current: int32(resp.Page.Current),
			Next:    int32(resp.Page.Next),
			Total:   int32(resp.Page.Total),
		},
	}, nil
}

func (e indexerService) GetSweptCommitmentTx(ctx context.Context, request *arkv1.GetSweptCommitmentTxRequest) (*arkv1.GetSweptCommitmentTxResponse, error) {
	resp, err := e.indexerSvc.GetSweptCommitmentTx(ctx, request.Txid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get swept commitment tx: %v", err)
	}

	return &arkv1.GetSweptCommitmentTxResponse{
		SweptBy: resp.SweptBy,
	}, nil
}

func (e indexerService) SubscribeForAddresses(
	request *arkv1.SubscribeForAddressesRequest, server arkv1.IndexerService_SubscribeForAddressesServer,
) error {
	//TODO implement me
	panic("implement me")
}
