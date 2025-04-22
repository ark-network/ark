package handlers

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

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
	txid, err := parseTxid(request.GetTxid())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetCommitmentTxInfo(ctx, txid)
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
	batchOutpoint, err := parseOutpoint(request.GetBatchOutpoint())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetVtxoTree(ctx, *batchOutpoint, page)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get vtxo tree: %v", err)
	}

	nodes := make([]*arkv1.IndexerNode, len(resp.Nodes))
	for i, node := range resp.Nodes {
		nodes[i] = &arkv1.IndexerNode{
			Txid:       node.Txid,
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
	batchOutpoint, err := parseOutpoint(request.GetBatchOutpoint())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetForfeitTxs(ctx, *batchOutpoint, page)
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
	batchOutpoint, err := parseOutpoint(request.GetBatchOutpoint())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetConnectors(ctx, *batchOutpoint, page)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get connectors: %v", err)
	}

	connectors := make([]*arkv1.IndexerNode, len(resp.Connectors))
	for i, connector := range resp.Connectors {
		connectors[i] = &arkv1.IndexerNode{
			Txid:       connector.Txid,
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
	address, err := parseArkAddress(request.GetAddress())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetSpendableVtxos(ctx, address, page)
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
			IsLeaf:    vtxo.RedeemTx == "",
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

func (e indexerService) GetTransactionHistory(
	ctx context.Context, request *arkv1.GetTransactionHistoryRequest,
) (*arkv1.GetTransactionHistoryResponse, error) {
	pubkey, err := parseArkAddress(request.GetAddress())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	startTime, err := parseTimestamp(request.GetStartTime())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	endTime, err := parseTimestamp(request.GetEndTime())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetTransactionHistory(ctx, pubkey, startTime, endTime, page)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get transaction history: %v", err)
	}

	history := make([]*arkv1.IndexerTxHistoryRecord, 0, len(resp.Records))
	for _, record := range resp.Records {
		historyRecord := &arkv1.IndexerTxHistoryRecord{
			Type:        arkv1.IndexerTxType(record.Type),
			Amount:      record.Amount,
			CreatedAt:   record.CreatedAt.Unix(),
			ConfirmedAt: record.ConfirmedAt,
			IsSettled:   record.Settled,
		}
		if record.CommitmentTxid != "" {
			historyRecord.Key = &arkv1.IndexerTxHistoryRecord_CommitmentTxid{
				CommitmentTxid: record.CommitmentTxid,
			}
		}
		if record.VirtualTxid != "" {
			historyRecord.Key = &arkv1.IndexerTxHistoryRecord_VirtualTxid{
				VirtualTxid: record.VirtualTxid,
			}
		}
		history = append(history, historyRecord)
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
	outpoint, err := parseOutpoint(request.GetOutpoint())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetVtxoChain(ctx, *outpoint, page)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get vtxo chain: %v", err)
	}

	graph := make(map[string]*arkv1.IndexerTransactions)
	for key, chain := range resp.Transactions {
		txs := make([]*arkv1.IndexerChain, 0, len(chain.Txs))
		for _, tx := range chain.Txs {
			var txType arkv1.IndexerChainedTxType
			switch strings.ToLower(tx.Type) {
			case "commitment":
				txType = arkv1.IndexerChainedTxType_INDEXER_CHAINED_TX_TYPE_COMMITMENT
			case "virtual":
				txType = arkv1.IndexerChainedTxType_INDEXER_CHAINED_TX_TYPE_VIRTUAL
			default:
				txType = arkv1.IndexerChainedTxType_INDEXER_CHAINED_TX_TYPE_UNSPECIFIED
			}
			txs = append(txs, &arkv1.IndexerChain{
				Txid: tx.Txid,
				Type: txType,
			})
		}
		graph[key] = &arkv1.IndexerTransactions{
			Txs:       txs,
			ExpiresAt: chain.ExpiresAt,
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
	txids, err := parseTxids(request.GetTxids())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	page, err := parsePage(request.GetPage())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetVirtualTxs(ctx, txids, page)
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
	txid, err := parseTxid(request.GetTxid())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := e.indexerSvc.GetSweptCommitmentTx(ctx, txid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get swept commitment tx: %v", err)
	}

	return &arkv1.GetSweptCommitmentTxResponse{
		SweptBy: resp.SweptBy,
	}, nil
}

func parseTxid(txid string) (string, error) {
	if txid == "" {
		return "", fmt.Errorf("missing txid")
	}
	buf, err := hex.DecodeString(txid)
	if err != nil {
		return "", fmt.Errorf("invalid txid format")
	}
	if len(buf) != 32 {
		return "", fmt.Errorf("invalid txid length")
	}
	return txid, nil
}

func parseOutpoint(outpoint *arkv1.IndexerOutpoint) (*application.Outpoint, error) {
	if outpoint == nil {
		return nil, fmt.Errorf("missing outpoint")
	}
	txid, err := parseTxid(outpoint.Txid)
	if err != nil {
		return nil, err
	}
	return &application.Outpoint{
		Txid: txid,
		Vout: outpoint.GetVout(),
	}, nil
}

func parsePage(page *arkv1.IndexerPageRequest) (*application.Page, error) {
	if page == nil {
		return nil, nil
	}
	if page.Size <= 0 {
		return nil, fmt.Errorf("invalid page size")
	}
	if page.Index < 0 {
		return nil, fmt.Errorf("invalid page index")
	}
	return &application.Page{
		PageSize: int(page.Size),
		PageNum:  int(page.Index),
	}, nil
}

func parseTxids(txids []string) ([]string, error) {
	if len(txids) == 0 {
		return nil, fmt.Errorf("missing txids")
	}
	for _, txid := range txids {
		if _, err := parseTxid(txid); err != nil {
			return nil, err
		}
	}
	return txids, nil
}

func parseTimestamp(timestamp int64) (int64, error) {
	if timestamp <= 0 {
		return 0, nil
	}
	return timestamp, nil
}
