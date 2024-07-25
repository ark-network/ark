package sqlitedb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/infrastructure/db/sqlite/sqlc/queries"
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

		if len(round.ForfeitTxs) > 0 || len(round.Connectors) > 0 || len(round.CongestionTree) > 0 {
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

			for level, levelTxs := range round.CongestionTree {
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

		if len(round.Payments) > 0 {
			for _, payment := range round.Payments {
				if err := querierWithTx.UpsertPayment(
					ctx,
					queries.UpsertPaymentParams{
						ID:      payment.Id,
						RoundID: round.Id,
					},
				); err != nil {
					return fmt.Errorf("failed to upsert payment: %w", err)
				}

				for _, receiver := range payment.Receivers {
					if err := querierWithTx.UpsertReceiver(
						ctx,
						queries.UpsertReceiverParams{
							PaymentID:      payment.Id,
							Pubkey:         receiver.Pubkey,
							Amount:         int64(receiver.Amount),
							OnchainAddress: receiver.OnchainAddress,
						},
					); err != nil {
						return fmt.Errorf("failed to upsert receiver: %w", err)
					}
				}

				for _, input := range payment.Inputs {
					if err := querierWithTx.UpdateVtxoPaymentId(
						ctx,
						queries.UpdateVtxoPaymentIdParams{
							PaymentID: sql.NullString{
								String: payment.Id,
								Valid:  true,
							},
							Txid: input.Txid,
							Vout: int64(input.VOut),
						},
					); err != nil {
						return fmt.Errorf("failed to update vtxo payment id: %w", err)
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

	rvs := make([]roundPaymentTxReceiverVtxoRow, 0, len(rows))
	for _, row := range rows {
		rvs = append(rvs, roundPaymentTxReceiverVtxoRow{
			round:    row.Round,
			payment:  row.Payment,
			tx:       row.Tx,
			receiver: row.Receiver,
			vtxo:     row.Vtxo,
		})
	}

	rounds, err := readRoundRows(rvs)
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

	rvs := make([]roundPaymentTxReceiverVtxoRow, 0, len(rows))
	for _, row := range rows {
		rvs = append(rvs, roundPaymentTxReceiverVtxoRow{
			round:    row.Round,
			payment:  row.Payment,
			tx:       row.Tx,
			receiver: row.Receiver,
			vtxo:     row.Vtxo,
		})
	}

	rounds, err := readRoundRows(rvs)
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

	rvs := make([]roundPaymentTxReceiverVtxoRow, 0, len(rows))
	for _, row := range rows {
		rvs = append(rvs, roundPaymentTxReceiverVtxoRow{
			round:    row.Round,
			payment:  row.Payment,
			tx:       row.Tx,
			receiver: row.Receiver,
			vtxo:     row.Vtxo,
		})
	}

	rounds, err := readRoundRows(rvs)
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

	rvs := make([]roundPaymentTxReceiverVtxoRow, 0, len(rows))
	for _, row := range rows {
		rvs = append(rvs, roundPaymentTxReceiverVtxoRow{
			round:    row.Round,
			payment:  row.Payment,
			tx:       row.Tx,
			receiver: row.Receiver,
			vtxo:     row.Vtxo,
		})
	}

	rounds, err := readRoundRows(rvs)
	if err != nil {
		return nil, err
	}

	res := make([]domain.Round, 0)

	for _, round := range rounds {
		res = append(res, *round)
	}

	return res, nil
}

func rowToReceiver(row queries.Receiver) domain.Receiver {
	return domain.Receiver{
		Pubkey:         row.Pubkey,
		Amount:         uint64(row.Amount),
		OnchainAddress: row.OnchainAddress,
	}
}

type roundPaymentTxReceiverVtxoRow struct {
	round    queries.Round
	payment  queries.Payment
	tx       queries.Tx
	receiver queries.Receiver
	vtxo     queries.Vtxo
}

func readRoundRows(rows []roundPaymentTxReceiverVtxoRow) ([]*domain.Round, error) {
	rounds := make(map[string]*domain.Round)

	for _, v := range rows {
		var round *domain.Round
		var ok bool

		if v.round.ID != "" {
			continue
		}

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
				Payments:         make(map[string]domain.Payment),
			}
		}

		if v.payment.ID != "" {
			payment, ok := round.Payments[v.payment.ID]
			if !ok {
				payment = domain.Payment{
					Id:        v.payment.ID,
					Inputs:    make([]domain.Vtxo, 0),
					Receivers: make([]domain.Receiver, 0),
				}
				round.Payments[v.payment.ID] = payment
			}

			if v.vtxo.PaymentID.Valid {
				payment, ok = round.Payments[v.vtxo.PaymentID.String]
				if !ok {
					payment = domain.Payment{
						Id:        v.vtxo.PaymentID.String,
						Inputs:    make([]domain.Vtxo, 0),
						Receivers: make([]domain.Receiver, 0),
					}
				}

				vtxo := rowToVtxo(v.vtxo)
				found := false

				for _, v := range payment.Inputs {
					if vtxo.Txid == v.Txid && vtxo.VOut == v.VOut {
						found = true
						break
					}
				}

				if !found {
					payment.Inputs = append(payment.Inputs, rowToVtxo(v.vtxo))
					round.Payments[v.vtxo.PaymentID.String] = payment
				}
			}

			if v.receiver.PaymentID != "" {
				payment, ok = round.Payments[v.receiver.PaymentID]
				if !ok {
					payment = domain.Payment{
						Id:        v.receiver.PaymentID,
						Inputs:    make([]domain.Vtxo, 0),
						Receivers: make([]domain.Receiver, 0),
					}
				}

				rcv := rowToReceiver(v.receiver)

				found := false
				for _, rcv := range payment.Receivers {
					if rcv.Pubkey == v.receiver.Pubkey && int64(rcv.Amount) == v.receiver.Amount {
						found = true
						break
					}
				}
				if !found {
					payment.Receivers = append(payment.Receivers, rcv)
					round.Payments[v.receiver.PaymentID] = payment
				}
			}
		}

		if v.tx.Tx != "" {
			position := v.tx.Position
			switch v.tx.Type {
			case "forfeit":
				round.ForfeitTxs = extendArray(round.ForfeitTxs, int(position))
				round.ForfeitTxs[position] = v.tx.Tx
			case "connector":
				round.Connectors = extendArray(round.Connectors, int(position))
				round.Connectors[position] = v.tx.Tx
			case "tree":
				level := v.tx.TreeLevel
				round.CongestionTree = extendArray(round.CongestionTree, int(level.Int64))
				round.CongestionTree[int(level.Int64)] = extendArray(round.CongestionTree[int(level.Int64)], int(position))
				if round.CongestionTree[int(level.Int64)][position] == (tree.Node{}) {
					round.CongestionTree[int(level.Int64)][position] = tree.Node{
						Tx:         v.tx.Tx,
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
