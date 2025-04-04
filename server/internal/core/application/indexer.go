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
	"time"
)

const (
	maxPageSizeVtxoTree       = 300
	maxPageSizeConnector      = 300
	maxPageSizeForfeitTxs     = 500
	maxPageSizeSpendableVtxos = 100
	maxPageSizeTxHistory      = 200
	maxPageSizeVtxoChain      = 100
	maxPageSizeVirtualTxs     = 100
)

type IndexerService interface {
	GetCommitmentTxInfo(ctx context.Context, txid string) (*CommitmentTxResp, error)
	GetVtxoTree(ctx context.Context, req VtxoTreeReq) (*VtxoTreeResp, error)
	GetForfeitTxs(ctx context.Context, req ForfeitTxsReq) (*ForfeitTxsResp, error)
	GetConnectors(ctx context.Context, req ConnectorsReq) (*ConnectorResp, error)
	GetSpendableVtxos(ctx context.Context, req SpendableVtxosReq) (*SpendableVtxosResp, error)
	GetTransactionHistory(ctx context.Context, req TxHistoryReq) (*TxHistoryResp, error)
	GetVtxoChain(ctx context.Context, req VtxoChainReq) (*VtxoChainResp, error)
	GetVirtualTxs(ctx context.Context, req VirtualTxsReq) (*VirtualTxsResp, error)
	GetSweptCommitmentTx(ctx context.Context, txid string) (*SweptCommitmentTxResp, error)
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
) (*CommitmentTxResp, error) {
	round, err := i.repoManager.Rounds().GetRoundWithTxid(ctx, txid)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	var (
		totalBatchAmount   uint64 = 0
		totalForfeitAmount uint64 = 0
		totalInputVtxos    int32  = 0
	)
	for _, request := range round.TxRequests {
		for _, input := range request.Inputs {
			totalForfeitAmount += input.Amount
		}
		totalInputVtxos += int32(len(request.Inputs))

		for _, receiver := range request.Receivers {
			if !receiver.IsOnchain() {
				totalBatchAmount += receiver.Amount
			}
		}
	}

	batches := make(map[VOut]Batch)
	// TODO: currently commitment tx has only one batch, in future multiple batches will be supported
	batches[0] = Batch{
		TotalBatchAmount:   totalBatchAmount,
		TotalForfeitAmount: totalForfeitAmount,
		TotalInputVtxos:    totalInputVtxos,
		TotalOutputVtxos:   int32(len(leaves)),
		ExpiresAt:          vtxo[0].ExpireAt,
		Swept:              round.Swept,
	}

	return &CommitmentTxResp{
		StartedAt: round.StartingTimestamp,
		EndAt:     round.EndingTimestamp,
		Batches:   batches,
	}, nil
}

func (i *indexerService) GetVtxoTree(ctx context.Context, req VtxoTreeReq) (*VtxoTreeResp, error) {
	vtxoTree, err := i.repoManager.Rounds().GetVtxoTreeWithTxid(ctx, req.BatchOutpoint.Txid) //TODO repo methods needs to be updated with multiple batches in future
	if err != nil {
		return nil, err
	}

	nodes, pageResp := paginate(flattenNodes(vtxoTree), req.Page, maxPageSizeVtxoTree)

	return &VtxoTreeResp{
		Nodes: nodes,
		Page:  pageResp,
	}, nil
}

func (i *indexerService) GetForfeitTxs(ctx context.Context, req ForfeitTxsReq) (*ForfeitTxsResp, error) {
	round, err := i.repoManager.Rounds().GetRoundWithTxid(ctx, req.BatchOutpoint.Txid) //TODO batch thing
	if err != nil {
		return nil, err
	}

	txs := make([]string, 0, len(round.ForfeitTxs))
	for _, tx := range round.ForfeitTxs {
		txs = append(txs, tx.Txid)
	}

	forfeitTxs, pageResp := paginate(txs, req.Page, maxPageSizeForfeitTxs)

	return &ForfeitTxsResp{
		Txs:  forfeitTxs,
		Page: pageResp,
	}, nil

}

func (i *indexerService) GetConnectors(ctx context.Context, req ConnectorsReq) (*ConnectorResp, error) {
	round, err := i.repoManager.Rounds().GetRoundWithTxid(ctx, req.BatchOutpoint.Txid) //TODO batch thing
	if err != nil {
		return nil, err
	}

	connectors, pageResp := paginate(flattenNodes(round.Connectors), req.Page, maxPageSizeConnector)

	return &ConnectorResp{
		Connectors: connectors,
		Page:       pageResp,
	}, nil
}

func (i *indexerService) GetSpendableVtxos(ctx context.Context, req SpendableVtxosReq) (*SpendableVtxosResp, error) {
	decodedAddress, err := common.DecodeAddress(req.Address)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(schnorr.SerializePubKey(decodedAddress.Server), schnorr.SerializePubKey(i.pubkey)) {
		return nil, err
	}

	pubkey := hex.EncodeToString(schnorr.SerializePubKey(decodedAddress.VtxoTapKey))

	spendableVtxos, _, err := i.repoManager.Vtxos().GetAllNonRedeemedVtxos(ctx, pubkey)
	if err != nil {
		return nil, err
	}

	spendableVtxosPaged, pageResp := paginate(spendableVtxos, req.Page, maxPageSizeSpendableVtxos)

	return &SpendableVtxosResp{
		Vtxos: spendableVtxosPaged,
		Page:  pageResp,
	}, nil
}

func (i *indexerService) GetTransactionHistory(ctx context.Context, req TxHistoryReq) (*TxHistoryResp, error) {
	allVtxos, err := i.repoManager.Vtxos().GetAll(ctx)
	if err != nil {
		return nil, err
	}

	spendable := make([]domain.Vtxo, 0)
	spent := make([]domain.Vtxo, 0)

	for _, vtxo := range allVtxos {
		if vtxo.Spent || vtxo.Swept {
			spent = append(spent, vtxo)
		} else {
			spendable = append(spendable, vtxo)
		}
	}

	txs, err := vtxosToTxs(spendable, spent)
	if err != nil {
		return nil, err
	}

	txsPaged, pageResp := paginate(txs, req.Page, maxPageSizeTxHistory)

	return &TxHistoryResp{
		Records:    txsPaged,
		Pagination: pageResp,
	}, nil
}

type vtxoKeyWithCreatedAt struct {
	domain.VtxoKey
	CreatedAt int64
}

func (i *indexerService) GetVtxoChain(ctx context.Context, req VtxoChainReq) (*VtxoChainResp, error) {
	chainMap := make(map[vtxoKeyWithCreatedAt][]string)

	outpoint := domain.VtxoKey{
		Txid: req.VtxoKey.Txid,
		VOut: req.VtxoKey.Vout,
	}

	if err := i.buildChain(ctx, outpoint, chainMap, true); err != nil {
		return nil, err
	}

	chainSlice := make([]vtxoKeyWithCreatedAt, 0, len(chainMap))
	for vtxo := range chainMap {
		chainSlice = append(chainSlice, vtxo)
	}

	sort.Slice(chainSlice, func(i, j int) bool {
		return chainSlice[i].CreatedAt > chainSlice[j].CreatedAt
	})

	pagedChainSlice, pageResp := paginate(chainSlice, req.Page, maxPageSizeVtxoChain)

	txMap := make(map[string][]string)
	for _, vtxo := range pagedChainSlice {
		txMap[vtxo.Txid] = chainMap[vtxo]
	}

	return &VtxoChainResp{
		Transactions: txMap,
		Page:         pageResp,
	}, nil
}

func (i *indexerService) buildChain(
	ctx context.Context,
	outpoint domain.VtxoKey,
	chain map[vtxoKeyWithCreatedAt][]string,
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
	key := vtxoKeyWithCreatedAt{
		VtxoKey:   outpoint,
		CreatedAt: vtxo.CreatedAt,
	}
	if _, ok := chain[key]; !ok {
		chain[key] = make([]string, 0)
	} else {
		return nil
	}

	//finish chain if this is the leaf Vtxo
	if !vtxo.IsPending() {
		chain[key] = append(chain[key], vtxo.RoundTxid)
		return nil
	}

	redeemPsbt, err := psbt.NewFromRawBytes(strings.NewReader(vtxo.RedeemTx), true)
	if err != nil {
		return err
	}

	for _, in := range redeemPsbt.UnsignedTx.TxIn {
		chain[key] = append(chain[key], in.PreviousOutPoint.Hash.String())
		parentOutpoint := domain.VtxoKey{
			Txid: in.PreviousOutPoint.Hash.String(),
			VOut: in.PreviousOutPoint.Index,
		}

		if err := i.buildChain(ctx, parentOutpoint, chain, false); err != nil {
			return err
		}
	}

	return nil
}

func (i *indexerService) GetVirtualTxs(ctx context.Context, req VirtualTxsReq) (*VirtualTxsResp, error) {
	vtxos, err := i.repoManager.Vtxos().GetAll(ctx)
	if err != nil {
		return nil, err
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
			return nil, err
		}
		if _, ok := txIdsMap[redeemTx.UnsignedTx.TxHash().String()]; ok {
			txs = append(txs, vtxo.RedeemTx)
		}
	}

	vtxs, err := i.repoManager.Rounds().GetTxsWithTxids(ctx, req.TxIDs)
	if err != nil {
		return nil, err
	}
	for _, vtx := range vtxs {
		txs = append(txs, vtx)
	}

	virtualTxs, reps := paginate(txs, req.Page, maxPageSizeVirtualTxs)

	return &VirtualTxsResp{
		Transactions: virtualTxs,
		Page:         reps,
	}, nil
}

func (i *indexerService) GetSweptCommitmentTx(ctx context.Context, txid string) (*SweptCommitmentTxResp, error) {
	// TODO currently not possible to find swept commitment tx, we need either to scan explorer which would be inefficient
	// or to store sweep txs it in the database

	return &SweptCommitmentTxResp{}, nil
}

func paginate[T any](items []T, params PageReq, maxSize int) ([]T, PageResp) {
	if params.PageSize <= 0 {
		params.PageSize = maxSize
	}
	if params.PageNum <= 0 {
		params.PageNum = 1
	}

	totalCount := len(items)
	totalPages := int(math.Ceil(float64(totalCount) / float64(params.PageSize)))

	resp := PageResp{
		Current: params.PageNum,
		Next:    params.PageNum + 1,
		Total:   totalPages,
	}

	if params.PageNum > totalPages && totalCount > 0 {
		return []T{}, resp
	}

	startIndex := (params.PageNum - 1) * params.PageSize
	endIndex := startIndex + params.PageSize

	if startIndex >= totalCount {
		return []T{}, resp
	}

	if endIndex > totalCount {
		endIndex = totalCount
	}

	return items[startIndex:endIndex], resp
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

func vtxosToTxs(spendable, spent []domain.Vtxo) ([]TxHistoryRecord, error) {
	txs := make([]TxHistoryRecord, 0)

	// Receivals

	// All vtxos are receivals unless:
	// - they resulted from a settlement (either boarding or refresh)
	// - they are the change of a spend tx
	vtxosLeftToCheck := append([]domain.Vtxo{}, spent...)
	for _, vtxo := range append(spendable, spent...) {
		settleVtxos := findVtxosSpentInSettlement(vtxosLeftToCheck, vtxo)
		settleAmount := reduceVtxosAmount(settleVtxos)
		if vtxo.Amount <= settleAmount {
			continue // settlement or change, ignore
		}

		spentVtxos := findVtxosSpentInPayment(vtxosLeftToCheck, vtxo)
		spentAmount := reduceVtxosAmount(spentVtxos)
		if vtxo.Amount <= spentAmount {
			continue // settlement or change, ignore
		}

		txid := vtxo.RoundTxid
		settled := !vtxo.IsPending()
		if vtxo.IsPending() {
			txid = vtxo.Txid
			settled = vtxo.SpentBy != ""
		}

		txs = append(txs, TxHistoryRecord{
			Txid:      txid,
			Amount:    vtxo.Amount - settleAmount - spentAmount,
			Type:      TxReceived,
			CreatedAt: time.Unix(vtxo.CreatedAt, 0),
			Settled:   settled,
		})
	}

	// Sendings

	// All "spentBy" vtxos are payments unless:
	// - they are settlements

	// aggregate spent by spentId
	vtxosBySpentBy := make(map[string][]domain.Vtxo)
	for _, v := range spent {
		if len(v.SpentBy) <= 0 {
			continue
		}

		if _, ok := vtxosBySpentBy[v.SpentBy]; !ok {
			vtxosBySpentBy[v.SpentBy] = make([]domain.Vtxo, 0)
		}
		vtxosBySpentBy[v.SpentBy] = append(vtxosBySpentBy[v.SpentBy], v)
	}

	for sb := range vtxosBySpentBy {
		resultedVtxos := findVtxosResultedFromSpentBy(append(spendable, spent...), sb)
		resultedAmount := reduceVtxosAmount(resultedVtxos)
		spentAmount := reduceVtxosAmount(vtxosBySpentBy[sb])
		if spentAmount <= resultedAmount {
			continue // settlement or change, ignore
		}

		vtxo := getVtxo(resultedVtxos, vtxosBySpentBy[sb])

		txid := vtxo.RoundTxid
		if vtxo.IsPending() {
			txid = vtxo.Txid
		}

		txs = append(txs, TxHistoryRecord{
			Txid:      txid,
			Amount:    spentAmount - resultedAmount,
			Type:      TxSent,
			CreatedAt: time.Unix(vtxo.CreatedAt, 0),
			Settled:   true,
		})

	}

	sort.SliceStable(txs, func(i, j int) bool {
		return txs[i].CreatedAt.After(txs[j].CreatedAt)
	})

	return txs, nil
}

func findVtxosSpentInSettlement(vtxos []domain.Vtxo, vtxo domain.Vtxo) []domain.Vtxo {
	if vtxo.IsPending() {
		return nil
	}
	return findVtxosSpent(vtxos, vtxo.RoundTxid)
}

func findVtxosSpent(vtxos []domain.Vtxo, id string) []domain.Vtxo {
	var result []domain.Vtxo
	leftVtxos := make([]domain.Vtxo, 0)
	for _, v := range vtxos {
		if v.SpentBy == id {
			result = append(result, v)
		} else {
			leftVtxos = append(leftVtxos, v)
		}
	}
	// Update the given list with only the left vtxos.
	copy(vtxos, leftVtxos)
	return result
}

func reduceVtxosAmount(vtxos []domain.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

func findVtxosSpentInPayment(vtxos []domain.Vtxo, vtxo domain.Vtxo) []domain.Vtxo {
	return findVtxosSpent(vtxos, vtxo.Txid)
}

func findVtxosResultedFromSpentBy(vtxos []domain.Vtxo, spentByTxid string) []domain.Vtxo {
	var result []domain.Vtxo
	for _, v := range vtxos {
		if !v.IsPending() && v.RoundTxid == spentByTxid {
			result = append(result, v)
			break
		}
		if v.Txid == spentByTxid {
			result = append(result, v)
		}
	}
	return result
}

func getVtxo(usedVtxos []domain.Vtxo, spentByVtxos []domain.Vtxo) domain.Vtxo {
	if len(usedVtxos) > 0 {
		return usedVtxos[0]
	} else if len(spentByVtxos) > 0 {
		return spentByVtxos[0]
	}
	return domain.Vtxo{}
}
