package indexer

import (
	"context"
	"fmt"
	"strings"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/indexer"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type grpcClient struct {
	conn      *grpc.ClientConn
	svc       arkv1.IndexerServiceClient
	treeCache *utils.Cache[tree.TxTree]
}

func NewClient(serverUrl string) (indexer.Indexer, error) {
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

	svc := arkv1.NewIndexerServiceClient(conn)
	treeCache := utils.NewCache[tree.TxTree]()

	return &grpcClient{conn, svc, treeCache}, nil
}

func (a *grpcClient) GetCommitmentTx(ctx context.Context, txid string) (*indexer.CommitmentTx, error) {
	req := &arkv1.GetCommitmentTxRequest{
		Txid: txid,
	}
	resp, err := a.svc.GetCommitmentTx(ctx, req)
	if err != nil {
		return nil, err
	}

	batches := make(map[uint32]*indexer.Batch)
	for vout, batch := range resp.GetBatches() {
		batches[vout] = &indexer.Batch{
			TotalOutputAmount: batch.GetTotalOutputAmount(),
			TotalOutputVtxos:  batch.GetTotalOutputVtxos(),
			ExpiresAt:         batch.GetExpiresAt(),
			Swept:             batch.GetSwept(),
		}
	}

	return &indexer.CommitmentTx{
		StartedAt:         resp.GetStartedAt(),
		EndedAt:           resp.GetEndedAt(),
		TotalInputAmount:  resp.GetTotalInputAmount(),
		TotalInputVtxos:   resp.GetTotalInputVtxos(),
		TotalOutputAmount: resp.GetTotalOutputAmount(),
		TotalOutputVtxos:  resp.GetTotalOutputVtxos(),
		Batches:           batches,
	}, nil
}

func (a *grpcClient) GetCommitmentTxLeaves(
	ctx context.Context, txid string, opts ...indexer.RequestOption,
) (*indexer.CommitmentTxLeavesResponse, error) {
	var page *arkv1.IndexerPageRequest
	if len(opts) > 0 {
		opt := opts[0]
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
		}
	}

	req := &arkv1.GetCommitmentTxLeavesRequest{
		Txid: txid,
		Page: page,
	}

	resp, err := a.svc.GetCommitmentTxLeaves(ctx, req)
	if err != nil {
		return nil, err
	}

	leaves := make([]indexer.Outpoint, 0, len(resp.GetLeaves()))
	for _, leaf := range resp.GetLeaves() {
		leaves = append(leaves, indexer.Outpoint{
			Txid: leaf.GetTxid(),
			VOut: leaf.GetVout(),
		})
	}

	return &indexer.CommitmentTxLeavesResponse{
		Leaves: leaves,
		Page:   parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetVtxoTree(
	ctx context.Context, batchOutpoint indexer.Outpoint, opts ...indexer.RequestOption,
) (*indexer.VtxoTreeResponse, error) {
	var page *arkv1.IndexerPageRequest
	if len(opts) > 0 {
		opt := opts[0]
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
		}
	}

	req := &arkv1.GetVtxoTreeRequest{
		BatchOutpoint: &arkv1.IndexerOutpoint{
			Txid: batchOutpoint.Txid,
			Vout: batchOutpoint.VOut,
		},
		Page: page,
	}

	resp, err := a.svc.GetVtxoTree(ctx, req)
	if err != nil {
		return nil, err
	}

	nodes := make([]indexer.TxNode, 0, len(resp.GetVtxoTree()))
	for _, node := range resp.GetVtxoTree() {
		nodes = append(nodes, indexer.TxNode{
			Txid:       node.GetTxid(),
			ParentTxid: node.GetParentTxid(),
			Level:      node.GetLevel(),
			LevelIndex: node.GetLevelIndex(),
		})
	}

	return &indexer.VtxoTreeResponse{
		Tree: nodes,
		Page: parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetVtxoTreeLeaves(
	ctx context.Context, batchOutpoint indexer.Outpoint, opts ...indexer.RequestOption,
) (*indexer.VtxoTreeLeavesResponse, error) {
	var page *arkv1.IndexerPageRequest
	if len(opts) > 0 {
		opt := opts[0]
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
		}
	}

	req := &arkv1.GetVtxoTreeLeavesRequest{
		BatchOutpoint: &arkv1.IndexerOutpoint{
			Txid: batchOutpoint.Txid,
			Vout: batchOutpoint.VOut,
		},
		Page: page,
	}

	resp, err := a.svc.GetVtxoTreeLeaves(ctx, req)
	if err != nil {
		return nil, err
	}

	leaves := make([]indexer.Outpoint, 0, len(resp.GetLeaves()))
	for _, leaf := range resp.GetLeaves() {
		leaves = append(leaves, indexer.Outpoint{
			Txid: leaf.GetTxid(),
			VOut: leaf.GetVout(),
		})
	}

	return &indexer.VtxoTreeLeavesResponse{
		Leaves: leaves,
		Page:   parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetForfeitTxs(
	ctx context.Context, txid string, opts ...indexer.RequestOption,
) (*indexer.ForfeitTxsResponse, error) {
	var page *arkv1.IndexerPageRequest
	if len(opts) > 0 {
		opt := opts[0]
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
		}
	}

	req := &arkv1.GetForfeitTxsRequest{
		Txid: txid,
		Page: page,
	}

	resp, err := a.svc.GetForfeitTxs(ctx, req)
	if err != nil {
		return nil, err
	}

	return &indexer.ForfeitTxsResponse{
		Txids: resp.GetTxids(),
		Page:  parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetConnectors(
	ctx context.Context, txid string, opts ...indexer.RequestOption,
) (*indexer.ConnectorsResponse, error) {
	var page *arkv1.IndexerPageRequest
	if len(opts) > 0 {
		opt := opts[0]
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
		}
	}

	req := &arkv1.GetConnectorsRequest{
		Txid: txid,
		Page: page,
	}

	resp, err := a.svc.GetConnectors(ctx, req)
	if err != nil {
		return nil, err
	}

	connectors := make([]indexer.TxNode, 0, len(resp.GetConnectors()))
	for _, connector := range resp.GetConnectors() {
		connectors = append(connectors, indexer.TxNode{
			Txid:       connector.GetTxid(),
			ParentTxid: connector.GetParentTxid(),
			Level:      connector.GetLevel(),
			LevelIndex: connector.GetLevelIndex(),
		})
	}

	return &indexer.ConnectorsResponse{
		Tree: connectors,
		Page: parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetVtxos(
	ctx context.Context, opts ...indexer.GetVtxosRequestOption,
) (*indexer.VtxosResponse, error) {
	var page *arkv1.IndexerPageRequest
	var spendableOnly, spentOnly bool
	if len(opts) <= 0 {
		return nil, fmt.Errorf("missing opts")
	}
	opt := opts[0]
	if opt.GetPage() != nil {
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
		}
	}
	spendableOnly = opt.GetSpendableOnly()
	spentOnly = opt.GetSpentOnly()
	if spentOnly && spentOnly == spendableOnly {
		return nil, status.Errorf(codes.InvalidArgument, "spendableOnly and spentOnly cannot be both true")
	}
	if len(opt.GetOutpoints()) > 0 {
		resp, err := a.svc.GetVtxosByOutpoint(ctx, &arkv1.GetVtxosByOutpointRequest{
			Outpoints: opt.GetOutpoints(),
			Page:      page,
		})
		if err != nil {
			return nil, err
		}
		vtxos := make([]indexer.Vtxo, 0, len(resp.GetVtxos()))
		for _, vtxo := range resp.GetVtxos() {
			vtxos = append(vtxos, indexer.Vtxo{
				Outpoint: indexer.Outpoint{
					Txid: vtxo.GetOutpoint().GetTxid(),
					VOut: vtxo.GetOutpoint().GetVout(),
				},
				CreatedAt:      vtxo.GetCreatedAt(),
				ExpiresAt:      vtxo.GetExpiresAt(),
				Amount:         vtxo.GetAmount(),
				Script:         vtxo.GetScript(),
				IsLeaf:         vtxo.GetIsLeaf(),
				IsSwept:        vtxo.GetIsSwept(),
				IsSpent:        vtxo.GetIsSpent(),
				SpentBy:        vtxo.GetSpentBy(),
				CommitmentTxid: vtxo.GetCommitmentTxid(),
			})
		}

		return &indexer.VtxosResponse{
			Vtxos: vtxos,
			Page:  parsePage(resp.GetPage()),
		}, nil
	}

	req := &arkv1.GetVtxosRequest{
		Addresses:     opt.GetAddresses(),
		SpendableOnly: spendableOnly,
		SpentOnly:     spentOnly,
		Page:          page,
	}

	resp, err := a.svc.GetVtxos(ctx, req)
	if err != nil {
		return nil, err
	}

	vtxos := make([]indexer.Vtxo, 0, len(resp.GetVtxos()))
	for _, vtxo := range resp.GetVtxos() {
		vtxos = append(vtxos, indexer.Vtxo{
			Outpoint: indexer.Outpoint{
				Txid: vtxo.GetOutpoint().GetTxid(),
				VOut: vtxo.GetOutpoint().GetVout(),
			},
			CreatedAt:      vtxo.GetCreatedAt(),
			ExpiresAt:      vtxo.GetExpiresAt(),
			Amount:         vtxo.GetAmount(),
			Script:         vtxo.GetScript(),
			IsLeaf:         vtxo.GetIsLeaf(),
			IsSwept:        vtxo.GetIsSwept(),
			IsSpent:        vtxo.GetIsSpent(),
			SpentBy:        vtxo.GetSpentBy(),
			CommitmentTxid: vtxo.GetCommitmentTxid(),
		})
	}

	return &indexer.VtxosResponse{
		Vtxos: vtxos,
		Page:  parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetTransactionHistory(
	ctx context.Context, address string, opts ...indexer.GetTxHistoryRequestOption,
) (*indexer.TxHistoryResponse, error) {
	var page *arkv1.IndexerPageRequest
	var startTime, endTime time.Time
	if len(opts) > 0 {
		opt := opts[0]
		if opt.GetPage() != nil {
			page = &arkv1.IndexerPageRequest{
				Size:  opt.GetPage().Size,
				Index: opt.GetPage().Index,
			}
		}
		if !opt.GetStartTime().IsZero() {
			startTime = opt.GetStartTime()
		}
		if !opt.GetEndTime().IsZero() {
			endTime = opt.GetEndTime()
		}
	}

	if !startTime.IsZero() && !endTime.IsZero() && startTime.After(endTime) {
		return nil, status.Errorf(codes.InvalidArgument, "start_time must be before end_time")
	}

	var startTimeUnix, endTimeUnix int64
	if !startTime.IsZero() {
		startTimeUnix = startTime.Unix()
	}
	if !endTime.IsZero() {
		endTimeUnix = endTime.Unix()
	}

	req := &arkv1.GetTransactionHistoryRequest{
		Address:   address,
		StartTime: startTimeUnix,
		EndTime:   endTimeUnix,
		Page:      page,
	}

	resp, err := a.svc.GetTransactionHistory(ctx, req)
	if err != nil {
		return nil, err
	}

	history := make([]indexer.TxHistoryRecord, 0, len(resp.GetHistory()))
	for _, record := range resp.GetHistory() {
		history = append(history, indexer.TxHistoryRecord{
			CommitmentTxid: record.GetCommitmentTxid(),
			VirtualTxid:    record.GetVirtualTxid(),
			Type:           indexer.TxType(record.GetType()),
			Amount:         record.GetAmount(),
			CreatedAt:      record.GetCreatedAt(),
			IsSettled:      record.GetIsSettled(),
			SettledBy:      record.GetSettledBy(),
		})
	}

	return &indexer.TxHistoryResponse{
		History: history,
		Page:    parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetVtxoChain(
	ctx context.Context, outpoint indexer.Outpoint, opts ...indexer.RequestOption,
) (*indexer.VtxoChainResponse, error) {
	var page *arkv1.IndexerPageRequest
	if len(opts) > 0 {
		opt := opts[0]
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
		}
	}

	req := &arkv1.GetVtxoChainRequest{
		Outpoint: &arkv1.IndexerOutpoint{
			Txid: outpoint.Txid,
			Vout: outpoint.VOut,
		},
		Page: page,
	}

	resp, err := a.svc.GetVtxoChain(ctx, req)
	if err != nil {
		return nil, err
	}

	chain := make([]indexer.ChainWithExpiry, 0, len(resp.GetChain()))
	for _, c := range resp.GetChain() {
		chain = append(chain, indexer.ChainWithExpiry{
			Txid:      c.Txid,
			Spends:    txChain{c.GetSpends()}.parse(),
			ExpiresAt: c.GetExpiresAt(),
		})
	}

	return &indexer.VtxoChainResponse{
		Chain:              chain,
		Depth:              resp.GetDepth(),
		RootCommitmentTxid: resp.GetRootCommitmentTxid(),
		Page:               parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetVirtualTxs(
	ctx context.Context, txids []string, opts ...indexer.RequestOption,
) (*indexer.VirtualTxsResponse, error) {
	var page *arkv1.IndexerPageRequest
	if len(opts) > 0 {
		opt := opts[0]
		page = &arkv1.IndexerPageRequest{
			Size:  opt.GetPage().Size,
			Index: opt.GetPage().Index,
		}
	}

	req := &arkv1.GetVirtualTxsRequest{
		Txids: txids,
		Page:  page,
	}

	resp, err := a.svc.GetVirtualTxs(ctx, req)
	if err != nil {
		return nil, err
	}

	return &indexer.VirtualTxsResponse{
		Txs:  resp.GetTxs(),
		Page: parsePage(resp.GetPage()),
	}, nil
}

func (a *grpcClient) GetSweptCommitmentTx(ctx context.Context, txid string) ([]string, error) {
	req := &arkv1.GetSweptCommitmentTxRequest{
		Txid: txid,
	}

	resp, err := a.svc.GetSweptCommitmentTx(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.GetSweptBy(), nil
}

func parsePage(page *arkv1.IndexerPageResponse) *indexer.PageResponse {
	if page == nil {
		return nil
	}
	return &indexer.PageResponse{
		Current: page.GetCurrent(),
		Next:    page.GetNext(),
		Total:   page.GetTotal(),
	}
}

type txChain struct {
	chain []*arkv1.IndexerChainedTx
}

func (c txChain) parse() []indexer.ChainTx {
	txs := make([]indexer.ChainTx, 0, len(c.chain))
	for _, tx := range c.chain {
		txs = append(txs, indexer.ChainTx{
			Txid: tx.GetTxid(),
			Type: tx.GetType().String(),
		})
	}
	return txs
}
