package sqlitedb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/infrastructure/db/sqlite/sqlc/queries"
)

type roundRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewRoundRepository(config ...interface{}) (domain.RoundRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open round repository: invalid config, expected db at 0")
	}

	return &roundRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (r *roundRepository) Close() {
	_ = r.db.Close()
}

func (r *roundRepository) GetRoundsIds(
	ctx context.Context, startedAfter int64, startedBefore int64,
) ([]string, error) {
	var roundIDs []string
	if startedAfter == 0 && startedBefore == 0 {
		ids, err := r.querier.SelectRoundIds(ctx)
		if err != nil {
			return nil, err
		}

		roundIDs = ids
	} else {
		ids, err := r.querier.SelectRoundIdsInRange(
			ctx,
			queries.SelectRoundIdsInRangeParams{
				StartingTimestamp:   startedAfter,
				StartingTimestamp_2: startedBefore,
			},
		)
		if err != nil {
			return nil, err
		}

		roundIDs = ids
	}

	return roundIDs, nil
}

func (r *roundRepository) AddOrUpdateRound(ctx context.Context, round domain.Round) error {
	txBody := func(querierWithTx *queries.Queries) error {
		if err := querierWithTx.UpsertRound(
			ctx,
			queries.UpsertRoundParams{
				ID:                round.Id,
				StartingTimestamp: round.StartingTimestamp,
				EndingTimestamp:   round.EndingTimestamp,
				Ended:             round.Stage.Ended,
				Failed:            round.Stage.Failed,
				StageCode:         int64(round.Stage.Code),
				Txid:              round.Txid,
				UnsignedTx:        round.UnsignedTx,
				ConnectorAddress:  round.ConnectorAddress,
				DustAmount:        int64(round.DustAmount),
				Version:           int64(round.Version),
				Swept:             round.Swept,
			},
		); err != nil {
			return fmt.Errorf("failed to upsert round: %w", err)
		}

		if len(round.ForfeitTxs) > 0 || len(round.Connectors) > 0 || len(round.VtxoTree) > 0 {
			for pos, tx := range round.ForfeitTxs {
				if err := querierWithTx.UpsertTransaction(
					ctx,
					queries.UpsertTransactionParams{
						Tx:       tx,
						RoundID:  round.Id,
						Type:     "forfeit",
						Position: int64(pos),
					},
				); err != nil {
					return fmt.Errorf("failed to upsert forfeit transaction: %w", err)
				}
			}

			for pos, tx := range round.Connectors {
				if err := querierWithTx.UpsertTransaction(
					ctx,
					queries.UpsertTransactionParams{
						Tx:       tx,
						RoundID:  round.Id,
						Type:     "connector",
						Position: int64(pos),
					},
				); err != nil {
					return fmt.Errorf("failed to upsert connector transaction: %w", err)
				}
			}

			for level, levelTxs := range round.VtxoTree {
				for pos, tx := range levelTxs {
					if err := querierWithTx.UpsertTransaction(
						ctx,
						queries.UpsertTransactionParams{
							Tx:       tx.Tx,
							RoundID:  round.Id,
							Type:     "tree",
							Position: int64(pos),
							Txid: sql.NullString{
								String: tx.Txid,
								Valid:  true,
							},
							TreeLevel: sql.NullInt64{
								Int64: int64(level),
								Valid: true,
							},
							ParentTxid: sql.NullString{
								String: tx.ParentTxid,
								Valid:  true,
							},
							IsLeaf: sql.NullBool{
								Bool:  tx.Leaf,
								Valid: true,
							},
						},
					); err != nil {
						return fmt.Errorf("failed to upsert tree transaction: %w", err)
					}
				}
			}
		}

		if len(round.TxRequests) > 0 {
			for _, request := range round.TxRequests {
				if err := querierWithTx.UpsertTxRequest(
					ctx,
					queries.UpsertTxRequestParams{
						ID:      request.Id,
						RoundID: round.Id,
					},
				); err != nil {
					return fmt.Errorf("failed to upsert tx request: %w", err)
				}

				for _, receiver := range request.Receivers {
					if err := querierWithTx.UpsertReceiver(
						ctx,
						queries.UpsertReceiverParams{
							RequestID: request.Id,
							Amount:    int64(receiver.Amount),
							Pubkey: sql.NullString{
								String: receiver.PubKey,
								Valid:  len(receiver.PubKey) > 0,
							},
							OnchainAddress: sql.NullString{
								String: receiver.OnchainAddress,
								Valid:  len(receiver.OnchainAddress) > 0,
							},
						},
					); err != nil {
						return fmt.Errorf("failed to upsert receiver: %w", err)
					}
				}

				for _, input := range request.Inputs {
					if err := querierWithTx.UpdateVtxoRequestId(
						ctx,
						queries.UpdateVtxoRequestIdParams{
							RequestID: sql.NullString{
								String: request.Id,
								Valid:  true,
							},
							Txid: input.Txid,
							Vout: int64(input.VOut),
						},
					); err != nil {
						return fmt.Errorf("failed to update vtxo request id: %w", err)
					}
				}
			}
		}

		return nil
	}

	return execTx(ctx, r.db, txBody)
}

func (r *roundRepository) GetRoundWithId(ctx context.Context, id string) (*domain.Round, error) {
	rows, err := r.querier.SelectRoundWithRoundId(ctx, id)
	if err != nil {
		return nil, err
	}

	rvs := make([]combinedRow, 0, len(rows))
	for _, row := range rows {
		rvs = append(rvs, combinedRow{
			round:    row.Round,
			request:  row.RoundRequestVw,
			tx:       row.RoundTxVw,
			receiver: row.RequestReceiverVw,
			vtxo:     row.RequestVtxoVw,
		})
	}

	rounds, err := rowsToRounds(rvs)
	if err != nil {
		return nil, err
	}

	if len(rounds) > 0 {
		return rounds[0], nil
	}

	return nil, errors.New("round not found")
}

func (r *roundRepository) GetRoundWithTxid(ctx context.Context, txid string) (*domain.Round, error) {
	rows, err := r.querier.SelectRoundWithRoundTxId(ctx, txid)
	if err != nil {
		return nil, err
	}

	rvs := make([]combinedRow, 0, len(rows))
	for _, row := range rows {
		rvs = append(rvs, combinedRow{
			round:    row.Round,
			request:  row.RoundRequestVw,
			tx:       row.RoundTxVw,
			receiver: row.RequestReceiverVw,
			vtxo:     row.RequestVtxoVw,
		})
	}

	rounds, err := rowsToRounds(rvs)
	if err != nil {
		return nil, err
	}

	if len(rounds) > 0 {
		return rounds[0], nil
	}

	return nil, errors.New("round not found")
}

func (r *roundRepository) GetSweepableRounds(ctx context.Context) ([]domain.Round, error) {
	rows, err := r.querier.SelectSweepableRounds(ctx)
	if err != nil {
		return nil, err
	}

	rvs := make([]combinedRow, 0, len(rows))
	for _, row := range rows {
		rvs = append(rvs, combinedRow{
			round:    row.Round,
			request:  row.RoundRequestVw,
			tx:       row.RoundTxVw,
			receiver: row.RequestReceiverVw,
			vtxo:     row.RequestVtxoVw,
		})
	}

	rounds, err := rowsToRounds(rvs)
	if err != nil {
		return nil, err
	}

	res := make([]domain.Round, 0)

	for _, round := range rounds {
		res = append(res, *round)
	}

	return res, nil
}

func (r *roundRepository) GetSweptRounds(ctx context.Context) ([]domain.Round, error) {
	rows, err := r.querier.SelectSweptRounds(ctx)
	if err != nil {
		return nil, err
	}

	rvs := make([]combinedRow, 0, len(rows))
	for _, row := range rows {
		rvs = append(rvs, combinedRow{
			round:    row.Round,
			request:  row.RoundRequestVw,
			tx:       row.RoundTxVw,
			receiver: row.RequestReceiverVw,
			vtxo:     row.RequestVtxoVw,
		})
	}

	rounds, err := rowsToRounds(rvs)
	if err != nil {
		return nil, err
	}

	res := make([]domain.Round, 0)

	for _, round := range rounds {
		res = append(res, *round)
	}

	return res, nil
}

func rowToReceiver(row queries.RequestReceiverVw) domain.Receiver {
	return domain.Receiver{
		Amount:         uint64(row.Amount.Int64),
		PubKey:         row.Pubkey.String,
		OnchainAddress: row.OnchainAddress.String,
	}
}

type combinedRow struct {
	round    queries.Round
	request  queries.RoundRequestVw
	tx       queries.RoundTxVw
	receiver queries.RequestReceiverVw
	vtxo     queries.RequestVtxoVw
}

func rowsToRounds(rows []combinedRow) ([]*domain.Round, error) {
	rounds := make(map[string]*domain.Round)

	for _, v := range rows {
		var round *domain.Round
		var ok bool

		round, ok = rounds[v.round.ID]
		if !ok {
			round = &domain.Round{
				Id:                v.round.ID,
				StartingTimestamp: v.round.StartingTimestamp,
				EndingTimestamp:   v.round.EndingTimestamp,
				Stage: domain.Stage{
					Ended:  v.round.Ended,
					Failed: v.round.Failed,
					Code:   domain.RoundStage(v.round.StageCode),
				},
				Txid:             v.round.Txid,
				UnsignedTx:       v.round.UnsignedTx,
				ConnectorAddress: v.round.ConnectorAddress,
				DustAmount:       uint64(v.round.DustAmount),
				Version:          uint(v.round.Version),
				Swept:            v.round.Swept,
				TxRequests:       make(map[string]domain.TxRequest),
			}
		}

		if v.request.ID.Valid {
			request, ok := round.TxRequests[v.request.ID.String]
			if !ok {
				request = domain.TxRequest{
					Id:        v.request.ID.String,
					Inputs:    make([]domain.Vtxo, 0),
					Receivers: make([]domain.Receiver, 0),
				}
				round.TxRequests[v.request.ID.String] = request
			}

			if v.vtxo.RequestID.Valid {
				request, ok = round.TxRequests[v.vtxo.RequestID.String]
				if !ok {
					request = domain.TxRequest{
						Id:        v.vtxo.RequestID.String,
						Inputs:    make([]domain.Vtxo, 0),
						Receivers: make([]domain.Receiver, 0),
					}
				}

				vtxo := combinedRowToVtxo(v.vtxo)
				found := false
				for _, v := range request.Inputs {
					if vtxo.Txid == v.Txid && vtxo.VOut == v.VOut {
						found = true
						break
					}
				}

				if !found {
					request.Inputs = append(request.Inputs, combinedRowToVtxo(v.vtxo))
					round.TxRequests[v.vtxo.RequestID.String] = request
				}
			}

			if v.receiver.RequestID.Valid {
				request, ok = round.TxRequests[v.receiver.RequestID.String]
				if !ok {
					request = domain.TxRequest{
						Id:        v.receiver.RequestID.String,
						Inputs:    make([]domain.Vtxo, 0),
						Receivers: make([]domain.Receiver, 0),
					}
				}

				rcv := rowToReceiver(v.receiver)

				found := false
				for _, rcv := range request.Receivers {
					if (v.receiver.Pubkey.Valid || v.receiver.OnchainAddress.Valid) && v.receiver.Amount.Valid {
						if rcv.PubKey == v.receiver.Pubkey.String && rcv.OnchainAddress == v.receiver.OnchainAddress.String && int64(rcv.Amount) == v.receiver.Amount.Int64 {
							found = true
							break
						}
					}
				}
				if !found {
					request.Receivers = append(request.Receivers, rcv)
					round.TxRequests[v.receiver.RequestID.String] = request
				}
			}
		}

		if v.tx.Tx.Valid && v.tx.Type.Valid && v.tx.Position.Valid {
			position := v.tx.Position
			switch v.tx.Type.String {
			case "forfeit":
				round.ForfeitTxs = extendArray(round.ForfeitTxs, int(position.Int64))
				round.ForfeitTxs[position.Int64] = v.tx.Tx.String
			case "connector":
				round.Connectors = extendArray(round.Connectors, int(position.Int64))
				round.Connectors[position.Int64] = v.tx.Tx.String
			case "tree":
				level := v.tx.TreeLevel
				round.VtxoTree = extendArray(round.VtxoTree, int(level.Int64))
				round.VtxoTree[int(level.Int64)] = extendArray(round.VtxoTree[int(level.Int64)], int(position.Int64))
				if round.VtxoTree[int(level.Int64)][position.Int64] == (tree.Node{}) {
					round.VtxoTree[int(level.Int64)][position.Int64] = tree.Node{
						Tx:         v.tx.Tx.String,
						Txid:       v.tx.Txid.String,
						ParentTxid: v.tx.ParentTxid.String,
						Leaf:       v.tx.IsLeaf.Bool,
					}
				}
			}
		}

		rounds[v.round.ID] = round
	}

	var result []*domain.Round

	for _, round := range rounds {
		result = append(result, round)
	}

	return result, nil
}

func combinedRowToVtxo(row queries.RequestVtxoVw) domain.Vtxo {
	return domain.Vtxo{
		VtxoKey: domain.VtxoKey{
			Txid: row.Txid.String,
			VOut: uint32(row.Vout.Int64),
		},
		Amount:    uint64(row.Amount.Int64),
		PubKey:    row.Pubkey.String,
		RoundTxid: row.RoundTx.String,
		SpentBy:   row.SpentBy.String,
		Spent:     row.Spent.Bool,
		Redeemed:  row.Redeemed.Bool,
		Swept:     row.Swept.Bool,
		ExpireAt:  row.ExpireAt.Int64,
	}
}
