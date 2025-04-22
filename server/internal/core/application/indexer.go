package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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
	GetVtxoTree(ctx context.Context, batchOutpoint Outpoint, page *Page) (*VtxoTreeResp, error)
	GetForfeitTxs(ctx context.Context, batchOutpoint Outpoint, page *Page) (*ForfeitTxsResp, error)
	GetConnectors(ctx context.Context, batchOutpoint Outpoint, page *Page) (*ConnectorResp, error)
	GetSpendableVtxos(ctx context.Context, address string, page *Page) (*SpendableVtxosResp, error)
	GetTransactionHistory(ctx context.Context, address string, start, end int64, page *Page) (*TxHistoryResp, error)
	GetVtxoChain(ctx context.Context, vtxoKey Outpoint, page *Page) (*VtxoChainResp, error)
	GetVirtualTxs(ctx context.Context, txids []string, page *Page) (*VirtualTxsResp, error)
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
	roundStats, err := i.repoManager.Rounds().GetRoundStats(ctx, txid)
	if err != nil {
		return nil, err
	}

	batches := make(map[VOut]Batch)
	// TODO: currently commitment tx has only one batch, in future multiple batches will be supported
	batches[0] = Batch{
		TotalBatchAmount:   roundStats.TotalBatchAmount,
		TotalForfeitAmount: roundStats.TotalForfeitAmount,
		TotalInputVtxos:    roundStats.TotalInputVtxos,
		TotalOutputVtxos:   roundStats.TotalOutputVtxos,
		ExpiresAt:          roundStats.ExpiresAt,
		Swept:              roundStats.Swept,
	}

	return &CommitmentTxResp{
		StartedAt: roundStats.Started,
		EndAt:     roundStats.Ended,
		Batches:   batches,
	}, nil
}

func (i *indexerService) GetVtxoTree(ctx context.Context, batchOutpoint Outpoint, page *Page) (*VtxoTreeResp, error) {
	vtxoTree, err := i.repoManager.Rounds().GetVtxoTreeWithTxid(ctx, batchOutpoint.Txid) //TODO repo methods needs to be updated with multiple batches in future
	if err != nil {
		return nil, err
	}

	nodes, pageResp := paginate(flattenNodes(vtxoTree), page, maxPageSizeVtxoTree)

	return &VtxoTreeResp{
		Nodes: nodes,
		Page:  pageResp,
	}, nil
}

func (i *indexerService) GetForfeitTxs(ctx context.Context, batchOutpoint Outpoint, page *Page) (*ForfeitTxsResp, error) {
	forfeitTxs, err := i.repoManager.Rounds().GetRoundForfeitTxs(ctx, batchOutpoint.Txid) //TODO batch thing
	if err != nil {
		return nil, err
	}

	txs := make([]string, 0, len(forfeitTxs))
	for _, tx := range forfeitTxs {
		txs = append(txs, tx.Txid)
	}

	res, pageResp := paginate(txs, page, maxPageSizeForfeitTxs)

	return &ForfeitTxsResp{
		Txs:  res,
		Page: pageResp,
	}, nil

}

func (i *indexerService) GetConnectors(ctx context.Context, batchOutpoint Outpoint, page *Page) (*ConnectorResp, error) {
	connectorTree, err := i.repoManager.Rounds().GetRoundConnectorTree(ctx, batchOutpoint.Txid) //TODO batch thing
	if err != nil {
		return nil, err
	}

	nodes, pageResp := paginate(flattenNodes(connectorTree), page, maxPageSizeVtxoTree)

	return &ConnectorResp{
		Connectors: nodes,
		Page:       pageResp,
	}, nil
}

func (i *indexerService) GetSpendableVtxos(ctx context.Context, address string, page *Page) (*SpendableVtxosResp, error) {
	decodedAddress, err := common.DecodeAddress(address)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(schnorr.SerializePubKey(decodedAddress.Server), schnorr.SerializePubKey(i.pubkey)) {
		return nil, err
	}

	pubkey := hex.EncodeToString(schnorr.SerializePubKey(decodedAddress.VtxoTapKey))

	vtxos, err := i.repoManager.Vtxos().GetSpendableVtxosWithPubKey(ctx, pubkey)
	if err != nil {
		return nil, err
	}

	spendableVtxosPaged, pageResp := paginate(vtxos, page, maxPageSizeSpendableVtxos)

	return &SpendableVtxosResp{
		Vtxos: spendableVtxosPaged,
		Page:  pageResp,
	}, nil
}

func (i *indexerService) GetTransactionHistory(
	ctx context.Context, pubkey string, start, end int64, page *Page,
) (*TxHistoryResp, error) {
	spendable, spent, err := i.repoManager.Vtxos().GetAllVtxosWithPubKey(ctx, pubkey)
	if err != nil {
		return nil, err
	}

	txs, err := vtxosToTxs(spendable, spent)
	if err != nil {
		return nil, err
	}

	txs = filterByDate(txs, start, end)
	txsPaged, pageResp := paginate(txs, page, maxPageSizeTxHistory)

	return &TxHistoryResp{
		Records:    txsPaged,
		Pagination: pageResp,
	}, nil
}

func filterByDate(txs []TxHistoryRecord, start, end int64) []TxHistoryRecord {
	if start == 0 && end == 0 {
		return txs
	}

	var filteredTxs []TxHistoryRecord
	for _, tx := range txs {
		switch {
		case start > 0 && end > 0:
			if tx.CreatedAt.Unix() >= start && tx.CreatedAt.Unix() <= end {
				filteredTxs = append(filteredTxs, tx)
			}
		case start > 0 && end == 0:
			if tx.CreatedAt.Unix() >= start {
				filteredTxs = append(filteredTxs, tx)
			}
		case end > 0 && start == 0:
			if tx.CreatedAt.Unix() <= end {
				filteredTxs = append(filteredTxs, tx)
			}
		}
	}
	return filteredTxs
}

type vtxoKeyWithCreatedAt struct {
	domain.VtxoKey
	CreatedAt int64
}

func (i *indexerService) GetVtxoChain(ctx context.Context, vtxoKey Outpoint, page *Page) (*VtxoChainResp, error) {
	chainMap := make(map[vtxoKeyWithCreatedAt]ChainWithExpiry)

	outpoint := domain.VtxoKey{
		Txid: vtxoKey.Txid,
		VOut: vtxoKey.Vout,
	}

	if err := i.buildChain(ctx, outpoint, chainMap, true); err != nil {
		return nil, err
	}

	chainSlice := make([]vtxoKeyWithCreatedAt, 0, len(chainMap))
	for vtxo := range chainMap {
		chainSlice = append(chainSlice, vtxo)
	}

	sort.Slice(chainSlice, func(i, j int) bool {
		return chainSlice[i].CreatedAt < chainSlice[j].CreatedAt
	})

	pagedChainSlice, pageResp := paginate(chainSlice, page, maxPageSizeVtxoChain)

	txMap := make(map[string]ChainWithExpiry)
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
	chain map[vtxoKeyWithCreatedAt]ChainWithExpiry,
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
		chain[key] = ChainWithExpiry{
			Txs:       make([]ChainTx, 0),
			ExpiresAt: vtxo.ExpireAt,
		}
	} else {
		return nil
	}

	//finish chain if this is the leaf Vtxo
	if !vtxo.IsPending() {
		txs := chain[key].Txs
		txs = append(txs, ChainTx{
			Txid: vtxo.RoundTxid,
			Type: "commitment",
		})
		chain[key] = ChainWithExpiry{
			Txs:       txs,
			ExpiresAt: chain[key].ExpiresAt,
		}
		return nil
	}

	redeemPsbt, err := psbt.NewFromRawBytes(strings.NewReader(vtxo.RedeemTx), true)
	if err != nil {
		return err
	}

	for _, in := range redeemPsbt.UnsignedTx.TxIn {
		txs := chain[key].Txs
		txs = append(txs, ChainTx{
			Txid: in.PreviousOutPoint.Hash.String(),
			Type: "virtual",
		})
		chain[key] = ChainWithExpiry{
			Txs:       txs,
			ExpiresAt: chain[key].ExpiresAt,
		}
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

func (i *indexerService) GetVirtualTxs(ctx context.Context, txids []string, page *Page) (*VirtualTxsResp, error) {
	txs, err := i.repoManager.Rounds().GetTxsWithTxids(ctx, txids)
	if err != nil {
		return nil, err
	}

	virtualTxs, reps := paginate(txs, page, maxPageSizeVirtualTxs)

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

func paginate[T any](items []T, params *Page, maxSize int) ([]T, PageResp) {
	if params == nil {
		return items, PageResp{}
	}
	if params.PageSize <= 0 {
		params.PageSize = maxSize
	}
	if params.PageNum <= 0 {
		params.PageNum = 1
	}

	totalCount := len(items)
	totalPages := int(math.Ceil(float64(totalCount) / float64(params.PageSize)))
	next := min(params.PageNum+1, totalPages)

	resp := PageResp{
		Current: params.PageNum,
		Next:    next,
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
