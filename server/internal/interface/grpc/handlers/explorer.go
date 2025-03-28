package handlers

import (
	"context"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/server/internal/core/application"
)

type explorerService struct {
	indexerSvc application.IndexerService
}

func NewExplorerServiceServer(indexerSvc application.IndexerService) arkv1.ExplorerServiceServer {
	return explorerService{
		indexerSvc: indexerSvc,
	}
}

func (e explorerService) GetCommitmentTxInfo(
	ctx context.Context, request *arkv1.GetCommitmentTxInfoRequest,
) (*arkv1.GetCommitmentTxInfoResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (e explorerService) GetVtxoTree(
	ctx context.Context, request *arkv1.GetVtxoTreeRequest,
) (*arkv1.GetVtxoTreeResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (e explorerService) GetForfeitTxs(
	ctx context.Context, request *arkv1.GetForfeitTxsRequest) (*arkv1.GetForfeitTxsResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (e explorerService) GetConnectors(
	ctx context.Context, request *arkv1.GetConnectorsRequest,
) (*arkv1.GetConnectorsResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (e explorerService) GetSpendableVtxos(
	ctx context.Context, request *arkv1.GetSpendableVtxosRequest,
) (*arkv1.GetSpendableVtxosResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (e explorerService) GetTransactionHistory(
	ctx context.Context, request *arkv1.GetTransactionHistoryRequest,
) (*arkv1.GetTransactionHistoryResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (e explorerService) GetTransactionChain(
	ctx context.Context, request *arkv1.GetTransactionChainRequest,
) (*arkv1.GetTransactionChainResponse, error) {
	//TODO implement me
	panic("implement me")
}
