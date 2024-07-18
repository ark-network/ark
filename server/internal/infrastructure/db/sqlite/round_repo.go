package sqlitedb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
)

const (
	createReceiverTable = `
CREATE TABLE IF NOT EXISTS receiver (
	payment_id TEXT NOT NULL,
	pubkey TEXT NOT NULL,
	amount INTEGER NOT NULL,
	onchain_address TEXT NOT NULL,
	FOREIGN KEY (payment_id) REFERENCES payment(id)
	PRIMARY KEY (payment_id, pubkey)
);
`

	createPaymentTable = `
CREATE TABLE IF NOT EXISTS payment (
	id TEXT PRIMARY KEY,
	round_id TEXT NOT NULL,
	FOREIGN KEY (round_id) REFERENCES round(id)
);
`

	createRoundTable = `
CREATE TABLE IF NOT EXISTS round (
	id TEXT PRIMARY KEY,
	starting_timestamp INTEGER NOT NULL,
	ending_timestamp INTEGER NOT NULL,
	ended BOOLEAN NOT NULL,
	failed BOOLEAN NOT NULL,
	stage_code INTEGER NOT NULL,
	txid TEXT NOT NULL,
	unsigned_tx TEXT NOT NULL,
	connector_address TEXT NOT NULL,
	dust_amount INTEGER NOT NULL,
	version INTEGER NOT NULL,
	swept BOOLEAN NOT NULL
);
`

	createTransactionTable = `
CREATE TABLE IF NOT EXISTS tx (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	tx TEXT NOT NULL,
	round_id TEXT NOT NULL,
	type TEXT NOT NULL,
	position INTEGER NOT NULL,
	txid TEXT,
	tree_level INTEGER,
	parent_txid TEXT,
	is_leaf BOOLEAN,
	FOREIGN KEY (round_id) REFERENCES round(id)
);
`
	upsertTransaction = `
INSERT INTO tx (
	tx, round_id, type, position, txid, tree_level, parent_txid, is_leaf
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	tx = EXCLUDED.tx,
	round_id = EXCLUDED.round_id,
	type = EXCLUDED.type,
	position = EXCLUDED.position,
	txid = EXCLUDED.txid,
	tree_level = EXCLUDED.tree_level,
	parent_txid = EXCLUDED.parent_txid,
	is_leaf = EXCLUDED.is_leaf;
`

	upsertRound = `
INSERT INTO round (
	id, 
	starting_timestamp, 
	ending_timestamp, 
	ended, failed, 
	stage_code, 
	txid, 
	unsigned_tx, 
	connector_address, 
	dust_amount, 
	version, 
	swept
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	starting_timestamp = EXCLUDED.starting_timestamp,
	ending_timestamp = EXCLUDED.ending_timestamp,
	ended = EXCLUDED.ended,
	failed = EXCLUDED.failed,
	stage_code = EXCLUDED.stage_code,
	txid = EXCLUDED.txid,
	unsigned_tx = EXCLUDED.unsigned_tx,
	connector_address = EXCLUDED.connector_address,
	dust_amount = EXCLUDED.dust_amount,
	version = EXCLUDED.version,
	swept = EXCLUDED.swept;
`

	upsertPayment = `
INSERT INTO payment (id, round_id) VALUES (?, ?) 
ON CONFLICT(id) DO UPDATE SET round_id = EXCLUDED.round_id;
`

	upsertReceiver = `
INSERT INTO receiver (payment_id, pubkey, amount, onchain_address) VALUES (?, ?, ?, ?) 
ON CONFLICT(payment_id, pubkey) DO UPDATE SET 
	amount = EXCLUDED.amount,
	onchain_address = EXCLUDED.onchain_address,
	pubkey = EXCLUDED.pubkey;
`

	updateVtxoPaymentId = `
UPDATE vtxo SET payment_id = ? WHERE txid = ? AND vout = ?
`

	selectRound = `
SELECT round.id, round.starting_timestamp, round.ending_timestamp, round.ended, round.failed, round.stage_code, round.txid, 
round.unsigned_tx, round.connector_address, round.dust_amount, round.version, round.swept, payment.id, receiver.payment_id, 
receiver.pubkey, receiver.amount, receiver.onchain_address, vtxo.txid, vtxo.vout, vtxo.pubkey, vtxo.amount, 
vtxo.pool_tx, vtxo.spent_by, vtxo.spent, vtxo.redeemed, vtxo.swept, vtxo.expire_at, vtxo.payment_id, 
tx.tx, tx.type, tx.position, tx.txid, 
tx.tree_level, tx.parent_txid, tx.is_leaf
FROM round 
LEFT OUTER JOIN payment ON round.id=payment.round_id 
LEFT OUTER JOIN tx ON round.id=tx.round_id
LEFT OUTER JOIN receiver ON payment.id=receiver.payment_id
LEFT OUTER JOIN vtxo ON payment.id=vtxo.payment_id
`

	selectRoundWithId     = selectRound + " WHERE round.id = ?;"
	selectRoundWithTxId   = selectRound + " WHERE round.txid = ?;"
	selectSweepableRounds = selectRound + " WHERE round.swept = false AND round.ended = true AND round.failed = false;"
	selectSweptRounds     = selectRound + " WHERE round.swept = true AND round.failed = false AND round.ended = true AND round.connector_address <> '';"

	selectRoundIdsInRange = `
SELECT id FROM round WHERE starting_timestamp > ? AND starting_timestamp < ?;
`

	selectRoundIds = `
SELECT id FROM round;
`
)

type receiverRow struct {
	paymentId      *string
	pubkey         *string
	amount         *uint64
	onchainAddress *string
}

type paymentRow struct {
	id *string
}

type transactionRow struct {
	tx         *string
	txType     *string
	position   *int
	txid       *string
	treeLevel  *int
	parentTxid *string
	isLeaf     *bool
}

type roundRow struct {
	id                *string
	startingTimestamp *int64
	endingTimestamp   *int64
	ended             *bool
	failed            *bool
	stageCode         *domain.RoundStage
	txid              *string
	unsignedTx        *string
	connectorAddress  *string
	dustAmount        *uint64
	version           *uint
	swept             *bool
}

type roundRepository struct {
	db *sql.DB
}

func NewRoundRepository(config ...interface{}) (domain.RoundRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open round repository: invalid config")
	}

	return newRoundRepository(db)
}

func newRoundRepository(db *sql.DB) (*roundRepository, error) {
	if _, err := db.Exec(createRoundTable); err != nil {
		return nil, err
	}

	if _, err := db.Exec(createPaymentTable); err != nil {
		return nil, err
	}

	if _, err := db.Exec(createReceiverTable); err != nil {
		return nil, err
	}

	if _, err := db.Exec(createTransactionTable); err != nil {
		return nil, err
	}

	return &roundRepository{db}, nil
}

func (r *roundRepository) Close() {
	_ = r.db.Close()
}

func (r *roundRepository) GetRoundsIds(ctx context.Context, startedAfter int64, startedBefore int64) ([]string, error) {
	var rows *sql.Rows

	if startedAfter == 0 && startedBefore == 0 {
		stmt, err := r.db.Prepare(selectRoundIds)
		if err != nil {
			return nil, err
		}
		defer stmt.Close()

		rows, err = stmt.Query()
		if err != nil {
			return nil, err
		}
	} else {
		stmt, err := r.db.Prepare(selectRoundIdsInRange)
		if err != nil {
			return nil, err
		}
		defer stmt.Close()

		rows, err = stmt.Query(startedAfter, startedBefore)
		if err != nil {
			return nil, err
		}
	}

	defer rows.Close()

	ids := make([]string, 0)

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}

		ids = append(ids, id)
	}

	return ids, nil
}

func (r *roundRepository) AddOrUpdateRound(ctx context.Context, round domain.Round) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(upsertRound)
	if err != nil {
		return err
	}

	defer stmt.Close()

	// insert round row
	_, err = stmt.Exec(
		round.Id,
		round.StartingTimestamp,
		round.EndingTimestamp,
		round.Stage.Ended,
		round.Stage.Failed,
		round.Stage.Code,
		round.Txid,
		round.UnsignedTx,
		round.ConnectorAddress,
		round.DustAmount,
		round.Version,
		round.Swept,
	)
	if err != nil {
		return err
	}

	// insert transactions rows
	if len(round.ForfeitTxs) > 0 || len(round.Connectors) > 0 || len(round.CongestionTree) > 0 {
		stmt, err = tx.Prepare(upsertTransaction)
		if err != nil {
			return err
		}

		defer stmt.Close()

		for pos, tx := range round.ForfeitTxs {
			_, err := stmt.Exec(tx, round.Id, "forfeit", pos, nil, nil, nil, nil)
			if err != nil {
				return err
			}
		}

		for pos, tx := range round.Connectors {
			_, err := stmt.Exec(tx, round.Id, "connector", pos, nil, nil, nil, nil)
			if err != nil {
				return err
			}
		}

		for level, levelTxs := range round.CongestionTree {
			for pos, tx := range levelTxs {
				_, err := stmt.Exec(tx.Tx, round.Id, "tree", pos, tx.Txid, level, tx.ParentTxid, tx.Leaf)
				if err != nil {
					return err
				}
			}
		}
	}

	// insert payments rows
	if len(round.Payments) > 0 {
		stmtUpsertPayment, err := tx.Prepare(upsertPayment)
		if err != nil {
			return err
		}
		defer stmtUpsertPayment.Close()

		for _, payment := range round.Payments {
			_, err = stmtUpsertPayment.Exec(payment.Id, round.Id)
			if err != nil {
				return err
			}

			stmtUpsertReceiver, err := tx.Prepare(upsertReceiver)
			if err != nil {
				return err
			}
			defer stmtUpsertReceiver.Close()

			for _, receiver := range payment.Receivers {
				_, err := stmtUpsertReceiver.Exec(payment.Id, receiver.Pubkey, receiver.Amount, receiver.OnchainAddress)
				if err != nil {
					return err
				}
			}

			stmtUpdatePaymentId, err := tx.Prepare(updateVtxoPaymentId)
			if err != nil {
				return err
			}
			defer stmtUpdatePaymentId.Close()

			for _, input := range payment.Inputs {
				_, err := stmtUpdatePaymentId.Exec(payment.Id, input.Txid, input.VOut)
				if err != nil {
					return err
				}
			}
		}
	}

	return tx.Commit()
}

func (r *roundRepository) GetRoundWithId(ctx context.Context, id string) (*domain.Round, error) {
	stmt, err := r.db.Prepare(selectRoundWithId)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.Query(id)
	if err != nil {
		return nil, err
	}

	rounds, err := readRoundRows(rows)
	if err != nil {
		return nil, err
	}

	if len(rounds) > 0 {
		return rounds[0], nil
	}

	return nil, errors.New("round not found")
}

func (r *roundRepository) GetRoundWithTxid(ctx context.Context, txid string) (*domain.Round, error) {
	stmt, err := r.db.Prepare(selectRoundWithTxId)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.Query(txid)
	if err != nil {
		return nil, err
	}

	rounds, err := readRoundRows(rows)
	if err != nil {
		return nil, err
	}

	if len(rounds) > 0 {
		return rounds[0], nil
	}

	return nil, errors.New("round not found")
}

func (r *roundRepository) GetSweepableRounds(ctx context.Context) ([]domain.Round, error) {
	stmt, err := r.db.Prepare(selectSweepableRounds)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.Query()
	if err != nil {
		return nil, err
	}

	rounds, err := readRoundRows(rows)
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
	stmt, err := r.db.Prepare(selectSweptRounds)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.Query()
	if err != nil {
		return nil, err
	}

	rounds, err := readRoundRows(rows)
	if err != nil {
		return nil, err
	}

	res := make([]domain.Round, 0)

	for _, round := range rounds {
		res = append(res, *round)
	}

	return res, nil
}

func rowToReceiver(row receiverRow) domain.Receiver {
	return domain.Receiver{
		Pubkey:         *row.pubkey,
		Amount:         *row.amount,
		OnchainAddress: *row.onchainAddress,
	}
}

func readRoundRows(rows *sql.Rows) ([]*domain.Round, error) {
	defer rows.Close()

	rounds := make(map[string]*domain.Round)

	for rows.Next() {
		var roundRow roundRow
		var paymentRow paymentRow
		var receiverRow receiverRow
		var vtxoRow vtxoRow
		var transactionRow transactionRow

		if err := rows.Scan(
			&roundRow.id,
			&roundRow.startingTimestamp,
			&roundRow.endingTimestamp,
			&roundRow.ended,
			&roundRow.failed,
			&roundRow.stageCode,
			&roundRow.txid,
			&roundRow.unsignedTx,
			&roundRow.connectorAddress,
			&roundRow.dustAmount,
			&roundRow.version,
			&roundRow.swept,
			&paymentRow.id,
			&receiverRow.paymentId,
			&receiverRow.pubkey,
			&receiverRow.amount,
			&receiverRow.onchainAddress,
			&vtxoRow.txid,
			&vtxoRow.vout,
			&vtxoRow.pubkey,
			&vtxoRow.amount,
			&vtxoRow.poolTx,
			&vtxoRow.spentBy,
			&vtxoRow.spent,
			&vtxoRow.redeemed,
			&vtxoRow.swept,
			&vtxoRow.expireAt,
			&vtxoRow.paymentID,
			&transactionRow.tx,
			&transactionRow.txType,
			&transactionRow.position,
			&transactionRow.txid,
			&transactionRow.treeLevel,
			&transactionRow.parentTxid,
			&transactionRow.isLeaf,
		); err != nil {
			return nil, err
		}

		var round *domain.Round
		var ok bool

		if roundRow.id == nil {
			continue
		}

		round, ok = rounds[*roundRow.id]
		if !ok {
			round = &domain.Round{
				Id:                *roundRow.id,
				StartingTimestamp: *roundRow.startingTimestamp,
				EndingTimestamp:   *roundRow.endingTimestamp,
				Stage: domain.Stage{
					Ended:  *roundRow.ended,
					Failed: *roundRow.failed,
					Code:   *roundRow.stageCode,
				},
				Txid:             *roundRow.txid,
				UnsignedTx:       *roundRow.unsignedTx,
				ConnectorAddress: *roundRow.connectorAddress,
				DustAmount:       *roundRow.dustAmount,
				Version:          *roundRow.version,
				Swept:            *roundRow.swept,
				Payments:         make(map[string]domain.Payment),
			}
		}

		if paymentRow.id != nil {
			payment, ok := round.Payments[*paymentRow.id]
			if !ok {
				payment = domain.Payment{
					Id:        *paymentRow.id,
					Inputs:    make([]domain.Vtxo, 0),
					Receivers: make([]domain.Receiver, 0),
				}
				round.Payments[*paymentRow.id] = payment
			}

			if vtxoRow.paymentID != nil {
				payment, ok = round.Payments[*vtxoRow.paymentID]
				if !ok {
					payment = domain.Payment{
						Id:        *vtxoRow.paymentID,
						Inputs:    make([]domain.Vtxo, 0),
						Receivers: make([]domain.Receiver, 0),
					}
				}

				vtxo := rowToVtxo(vtxoRow)
				found := false

				for _, v := range payment.Inputs {
					if vtxo.Txid == v.Txid && vtxo.VOut == v.VOut {
						found = true
						break
					}
				}

				if !found {
					payment.Inputs = append(payment.Inputs, rowToVtxo(vtxoRow))
					round.Payments[*vtxoRow.paymentID] = payment
				}
			}

			if receiverRow.paymentId != nil {
				payment, ok = round.Payments[*receiverRow.paymentId]
				if !ok {
					payment = domain.Payment{
						Id:        *receiverRow.paymentId,
						Inputs:    make([]domain.Vtxo, 0),
						Receivers: make([]domain.Receiver, 0),
					}
				}

				rcv := rowToReceiver(receiverRow)

				found := false
				for _, rcv := range payment.Receivers {
					if rcv.Pubkey == *receiverRow.pubkey && rcv.Amount == *receiverRow.amount {
						found = true
						break
					}
				}
				if !found {
					payment.Receivers = append(payment.Receivers, rcv)
					round.Payments[*receiverRow.paymentId] = payment
				}
			}
		}

		if transactionRow.tx != nil {
			position := *transactionRow.position
			switch *transactionRow.txType {
			case "forfeit":
				round.ForfeitTxs = extendArray(round.ForfeitTxs, position)
				round.ForfeitTxs[position] = *transactionRow.tx
			case "connector":
				round.Connectors = extendArray(round.Connectors, position)
				round.Connectors[position] = *transactionRow.tx
			case "tree":
				level := *transactionRow.treeLevel
				round.CongestionTree = extendArray(round.CongestionTree, level)
				round.CongestionTree[level] = extendArray(round.CongestionTree[level], position)
				if round.CongestionTree[level][position] == (tree.Node{}) {
					round.CongestionTree[level][position] = tree.Node{
						Tx:         *transactionRow.tx,
						Txid:       *transactionRow.txid,
						ParentTxid: *transactionRow.parentTxid,
						Leaf:       *transactionRow.isLeaf,
					}
				}
			}
		}

		rounds[*roundRow.id] = round
	}

	var result []*domain.Round

	for _, round := range rounds {
		result = append(result, round)
	}

	return result, nil
}
