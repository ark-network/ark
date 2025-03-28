package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math"
	"sort"
	"strings"
)

type IndexerService interface {
	GetCommitmentTxInfo(ctx context.Context, txid string) (CommitmentTxResp, error)
	GetVtxoTree(ctx context.Context, req VtxoTreeReq) (VtxoTreeResp, error)
	GetForfeitTxs(ctx context.Context, req ForfeitTxsReq) (ForfeitTxsResp, error)
	GetConnectors(ctx context.Context, req ConnectorsReq) (ConnectorResp, error)
	GetSpendableVtxos(ctx context.Context, req SpendableVtxosReq) (SpendableVtxosResp, error)
	GetTransactionHistory(ctx context.Context, req TxHistoryReq) (TxHistoryResp, error)
	GetVtxoChain(ctx context.Context, req VtxoChainReq) (VtxoChainResp, error)
	GetVirtualTxs(ctx context.Context, req VirtualTxsReq) (VirtualTxsResp, error)
	GetSweptCommitmentTx(ctx context.Context, txid string) (SweptCommitmentTxResp, error)
}

type indexerService struct {
	pubkey *secp256k1.PublicKey

	repoManager ports.RepoManager
}

func NewIndexerService(
	pubkey *secp256k1.PublicKey,
	repoManager ports.RepoManager,
) IndexerService {
	return &indexerService{
		pubkey:      pubkey,
		repoManager: repoManager,
	}
}

func (i *indexerService) GetCommitmentTxInfo(
	ctx context.Context, txid string,
) (CommitmentTxResp, error) {
	round, err := i.repoManager.Rounds().GetRoundWithTxid(ctx, txid)
	if err != nil {
		return CommitmentTxResp{}, err
	}

	leaves := round.VtxoTree.Leaves()

	vtxo, err := i.repoManager.Vtxos().GetVtxos(
		ctx,
		[]domain.VtxoKey{
			{
				Txid: leaves[0].Txid,
				VOut: 0,
			},
		},
	)
	if err != nil {
		return CommitmentTxResp{}, err
	}

	var (
		totalBatchAmount   uint64 = 0
		totalForfeitAmount uint64 = 0
		totalInputVtxos    int32  = 0
	)
	for _, request := range round.TxRequests {
		for _, input := range request.Inputs {
			totalInputVtxos += int32(input.Amount)
		}

		for _, receiver := range request.Receivers {
			totalBatchAmount += receiver.Amount
		}
	}

	forfeitInputs := make([]domain.VtxoKey, len(round.ForfeitTxs))
	for _, forfeit := range round.ForfeitTxs {
		forfeitTx, err := psbt.NewFromRawBytes(strings.NewReader(forfeit), true)
		if err != nil {
			return CommitmentTxResp{}, err
		}

		forfeitInputs = append(forfeitInputs, domain.VtxoKey{
			Txid: forfeitTx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String(),
			VOut: forfeitTx.UnsignedTx.TxIn[0].PreviousOutPoint.Index,
		})
	}

	vtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, forfeitInputs)
	if err != nil {
		return CommitmentTxResp{}, err
	}

	for _, v := range vtxos {
		totalForfeitAmount += v.Amount
	}

	batches := make(map[VOut]Batch)
	batches[0] = Batch{ //TODO currently commitment tx has only one batch, in future multiple batches will be supported
		TotalBatchAmount:   totalBatchAmount,
		TotalForfeitAmount: totalForfeitAmount,
		TotalInputVtxos:    totalInputVtxos,
		TotalOutputVtxos:   int32(len(leaves)),
		ExpiresAt:          vtxo[0].ExpireAt,
		Swept:              round.Swept,
	}

	return CommitmentTxResp{
		StartedAt: round.StartingTimestamp,
		EndAt:     round.EndingTimestamp,
		Batches:   batches,
	}, nil
}

func (i *indexerService) GetVtxoTree(ctx context.Context, req VtxoTreeReq) (VtxoTreeResp, error) {
	vtxoTree, err := i.repoManager.Rounds().GetVtxoTreeWithTxid(ctx, req.BatchOutpoint.Txid) //TODO repo methods needs to be updated with multiple batches in future
	if err != nil {
		return VtxoTreeResp{}, err
	}

	nodes, pageResp, err := paginate(flattenNodes(vtxoTree), req.Page)
	if err != nil {
		return VtxoTreeResp{}, err
	}

	return VtxoTreeResp{
		Nodes: nodes,
		Page:  pageResp,
	}, nil
}

func (i *indexerService) GetForfeitTxs(ctx context.Context, req ForfeitTxsReq) (ForfeitTxsResp, error) {
	round, err := i.repoManager.Rounds().GetRoundWithTxid(ctx, req.BatchOutpoint.Txid) //TODO batch thing
	if err != nil {
		return ForfeitTxsResp{}, err
	}

	forfeitTxs, pageResp, err := paginate(round.ForfeitTxs, req.Page)
	if err != nil {
		return ForfeitTxsResp{}, err
	}

	return ForfeitTxsResp{
		Txs:  forfeitTxs,
		Page: pageResp,
	}, nil

}

func (i *indexerService) GetConnectors(ctx context.Context, req ConnectorsReq) (ConnectorResp, error) {
	round, err := i.repoManager.Rounds().GetRoundWithTxid(ctx, req.BatchOutpoint.Txid) //TODO batch thing
	if err != nil {
		return ConnectorResp{}, err
	}

	connectors, pageResp, err := paginate(flattenNodes(round.Connectors), req.Page)
	if err != nil {
		return ConnectorResp{}, err
	}

	return ConnectorResp{
		Connectors: connectors,
		Page:       pageResp,
	}, nil
}

func (i *indexerService) GetSpendableVtxos(ctx context.Context, req SpendableVtxosReq) (SpendableVtxosResp, error) {
	decodedAddress, err := common.DecodeAddress(req.Address)
	if err != nil {
		return SpendableVtxosResp{}, err
	}

	if !bytes.Equal(schnorr.SerializePubKey(decodedAddress.Server), schnorr.SerializePubKey(i.pubkey)) {
		return SpendableVtxosResp{}, err
	}

	pubkey := hex.EncodeToString(schnorr.SerializePubKey(decodedAddress.VtxoTapKey))

	spendableVtxos, _, err := i.repoManager.Vtxos().GetAllNonRedeemedVtxos(ctx, pubkey)
	if err != nil {
		return SpendableVtxosResp{}, err
	}

	spendableVtxosPaged, pageResp, err := paginate(spendableVtxos, req.Page)
	if err != nil {
		return SpendableVtxosResp{}, err
	}

	return SpendableVtxosResp{
		Vtxos: spendableVtxosPaged,
		Page:  pageResp,
	}, nil
}

func (i *indexerService) GetTransactionHistory(ctx context.Context, req TxHistoryReq) (TxHistoryResp, error) {
	//TODO implement me
	panic("implement me")
}

func (i *indexerService) GetVtxoChain(ctx context.Context, req VtxoChainReq) (VtxoChainResp, error) {
	chainMap := make(map[Outpoint]domain.Vtxo)

	outpoint := domain.VtxoKey{
		Txid: req.VtxoKey.Txid,
		VOut: req.VtxoKey.Vout,
	}

	if err := i.buildChain(ctx, outpoint, chainMap, true); err != nil {
		return VtxoChainResp{}, err
	}

	chainSlice := make([]domain.Vtxo, 0, len(chainMap))
	for _, vtxo := range chainMap {
		chainSlice = append(chainSlice, vtxo)
	}

	sort.Slice(chainSlice, func(i, j int) bool {
		return chainSlice[i].CreatedAt > chainSlice[j].CreatedAt
	})

	pagedVtxos, pageResp, err := paginate(chainSlice, req.Page)
	if err != nil {
		return VtxoChainResp{}, err
	}

	txMap := make(map[Outpoint]string, len(pagedVtxos))
	for _, vtxo := range pagedVtxos {
		out := Outpoint{
			Txid: vtxo.Txid,
			Vout: vtxo.VOut,
		}
		txMap[out] = vtxo.RedeemTx
	}

	return VtxoChainResp{
		Transactions: txMap,
		Page:         pageResp,
	}, nil
}

func (i *indexerService) buildChain(
	ctx context.Context,
	outpoint domain.VtxoKey,
	chain map[Outpoint]domain.Vtxo,
	isFirst bool,
) error {
	vtxos, err := i.repoManager.Vtxos().GetVtxos(ctx, []domain.VtxoKey{outpoint})
	if err != nil {
		return err
	}

	if isFirst && len(vtxos) == 0 {
		return fmt.Errorf("vtxo not found for outpoint: %v", outpoint)
	}

	vtxo := vtxos[0]

	chain[Outpoint{Txid: vtxo.Txid, Vout: vtxo.VOut}] = vtxo

	if vtxo.RoundTxid != "" {
		return nil
	}

	redeemPsbt, err := psbt.NewFromRawBytes(strings.NewReader(vtxo.RedeemTx), true)
	if err != nil {
		return err
	}

	parentIn := redeemPsbt.UnsignedTx.TxIn[0]
	parentOutpoint := domain.VtxoKey{
		Txid: parentIn.PreviousOutPoint.Hash.String(),
		VOut: parentIn.PreviousOutPoint.Index,
	}

	return i.buildChain(ctx, parentOutpoint, chain, false)
}

func (i *indexerService) GetVirtualTxs(ctx context.Context, req VirtualTxsReq) (VirtualTxsResp, error) {
	vtxos, err := i.repoManager.Vtxos().GetAll(ctx)
	if err != nil {
		return VirtualTxsResp{}, err
	}

	txIdsMap := make(map[string]string)
	for _, v := range req.TxIDs {
		txIdsMap[v] = v
	}

	txs := make([]string, 0)
	for _, vtxo := range vtxos {
		if vtxo.RedeemTx == "" {
			continue
		}

		redeemTx, err := psbt.NewFromRawBytes(strings.NewReader(vtxo.RedeemTx), true)
		if err != nil {
			return VirtualTxsResp{}, err
		}
		if _, ok := txIdsMap[redeemTx.UnsignedTx.TxHash().String()]; ok {
			txs = append(txs, vtxo.RedeemTx)
		}
	}

	virtualTxs, reps, err := paginate(txs, req.Page)
	if err != nil {
		return VirtualTxsResp{}, err
	}

	return VirtualTxsResp{
		Transactions: virtualTxs,
		Page:         reps,
	}, nil
}

func (i *indexerService) GetSweptCommitmentTx(ctx context.Context, txid string) (SweptCommitmentTxResp, error) {
	// TODO currently not possible to find swept commitment tx, we need either to scan explorer which would be inefficient
	// or to store sweep txs it in the database

	return SweptCommitmentTxResp{}, nil
}

func paginate[T any](items []T, params PageReq) ([]T, PageResp, error) {
	if params.PageSize <= 0 {
		return nil, PageResp{}, fmt.Errorf("page size must be positive")
	}
	if params.PageNum <= 0 {
		return nil, PageResp{}, fmt.Errorf("page number must be positive")
	}

	totalCount := len(items)
	totalPages := int(math.Ceil(float64(totalCount) / float64(params.PageSize)))

	resp := PageResp{
		Current: params.PageNum,
		Next:    params.PageNum + 1,
		Total:   totalPages,
	}

	if params.PageNum > totalPages && totalCount > 0 {
		return []T{}, resp, nil
	}

	startIndex := (params.PageNum - 1) * params.PageSize
	endIndex := startIndex + params.PageSize

	if startIndex >= totalCount {
		return []T{}, resp, nil
	}

	if endIndex > totalCount {
		endIndex = totalCount
	}

	return items[startIndex:endIndex], resp, nil
}

func flattenNodes(t [][]tree.Node) []Node {
	var result []Node
	for level, nodes := range t {
		for idx, node := range nodes {
			result = append(result, Node{
				Txid:       node.Txid,
				Tx:         node.Tx,
				ParentTxid: node.ParentTxid,
				Level:      int32(level),
				LevelIndex: int32(idx),
			})
		}
	}
	return result
}
