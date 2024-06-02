package sqlitedb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	dbtypes "github.com/ark-network/ark/internal/infrastructure/db/types"
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
	txid TEXT NOT NULL,
	FOREIGN KEY (txid) REFERENCES round(txid)
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
	congestion_tree TEXT NOT NULL,
	forfeit_txs TEXT NOT NULL,
	connectors TEXT NOT NULL,
	connector_address TEXT NOT NULL,
	dust_amount INTEGER NOT NULL,
	version INTEGER NOT NULL,
	swept BOOLEAN NOT NULL
);
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
	congestion_tree, 
	forfeit_txs, 
	connectors, 
	connector_address, 
	dust_amount, 
	version, 
	swept
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	starting_timestamp = EXCLUDED.starting_timestamp,
	ending_timestamp = EXCLUDED.ending_timestamp,
	ended = EXCLUDED.ended,
	failed = EXCLUDED.failed,
	stage_code = EXCLUDED.stage_code,
	txid = EXCLUDED.txid,
	unsigned_tx = EXCLUDED.unsigned_tx,
	congestion_tree = EXCLUDED.congestion_tree,
	forfeit_txs = EXCLUDED.forfeit_txs,
	connectors = EXCLUDED.connectors,
	connector_address = EXCLUDED.connector_address,
	dust_amount = EXCLUDED.dust_amount,
	version = EXCLUDED.version,
	swept = EXCLUDED.swept;
`

	upsertPayment = `
INSERT INTO payment (id, txid) VALUES (?, ?) 
ON CONFLICT(id) DO UPDATE SET txid = EXCLUDED.txid;
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

	selectCurrentRound = `
SELECT round.id, round.starting_timestamp, round.ending_timestamp, round.ended, round.failed, round.stage_code, round.txid, round.unsigned_tx, round.congestion_tree, round.forfeit_txs, round.connectors, round.connector_address, round.dust_amount, round.version, round.swept, payment.id, receiver.payment_id, receiver.pubkey, receiver.amount, receiver.onchain_address, vtxo.txid, vtxo.vout, vtxo.pubkey, vtxo.amount, vtxo.pool_tx, vtxo.spent_by, vtxo.spent, vtxo.redeemed, vtxo.swept, vtxo.expire_at, vtxo.payment_id
FROM round 
LEFT OUTER JOIN payment ON round.txid=payment.txid 
LEFT OUTER JOIN receiver ON payment.id=receiver.payment_id
LEFT OUTER JOIN vtxo ON payment.id=vtxo.payment_id
WHERE round.ended = false AND round.failed = false
`

	selectRoundWithId = `
SELECT round.id, round.starting_timestamp, round.ending_timestamp, round.ended, round.failed, round.stage_code, round.txid, round.unsigned_tx, round.congestion_tree, round.forfeit_txs, round.connectors, round.connector_address, round.dust_amount, round.version, round.swept, payment.id, receiver.payment_id, receiver.pubkey, receiver.amount, receiver.onchain_address, vtxo.txid, vtxo.vout, vtxo.pubkey, vtxo.amount, vtxo.pool_tx, vtxo.spent_by, vtxo.spent, vtxo.redeemed, vtxo.swept, vtxo.expire_at, vtxo.payment_id
FROM round 
LEFT OUTER JOIN payment ON round.txid=payment.txid 
LEFT OUTER JOIN receiver ON payment.id=receiver.payment_id
LEFT OUTER JOIN vtxo ON payment.id=vtxo.payment_id
WHERE round.id = ?;
`

	selectRoundWithTxId = `
SELECT round.id, round.starting_timestamp, round.ending_timestamp, round.ended, round.failed, round.stage_code, round.txid, round.unsigned_tx, round.congestion_tree, round.forfeit_txs, round.connectors, round.connector_address, round.dust_amount, round.version, round.swept, payment.id, receiver.payment_id, receiver.pubkey, receiver.amount, receiver.onchain_address, vtxo.txid, vtxo.vout, vtxo.pubkey, vtxo.amount, vtxo.pool_tx, vtxo.spent_by, vtxo.spent, vtxo.redeemed, vtxo.swept, vtxo.expire_at, vtxo.payment_id
FROM round 
LEFT OUTER JOIN payment ON round.txid=payment.txid 
LEFT OUTER JOIN receiver ON payment.id=receiver.payment_id
LEFT OUTER JOIN vtxo ON payment.id=vtxo.payment_id
WHERE round.txid = ?;
`

	selectSweepableRounds = `
SELECT round.id, round.starting_timestamp, round.ending_timestamp, round.ended, round.failed, round.stage_code, round.txid, round.unsigned_tx, round.congestion_tree, round.forfeit_txs, round.connectors, round.connector_address, round.dust_amount, round.version, round.swept, payment.id, receiver.payment_id, receiver.pubkey, receiver.amount, receiver.onchain_address, vtxo.txid, vtxo.vout, vtxo.pubkey, vtxo.amount, vtxo.pool_tx, vtxo.spent_by, vtxo.spent, vtxo.redeemed, vtxo.swept, vtxo.expire_at, vtxo.payment_id
FROM round 
LEFT OUTER JOIN payment ON round.txid=payment.txid 
LEFT OUTER JOIN receiver ON payment.id=receiver.payment_id
LEFT OUTER JOIN vtxo ON payment.id=vtxo.payment_id
WHERE round.swept = false AND round.ended = true AND round.failed = false;
`

	selectSweptRounds = `
SELECT round.id, round.starting_timestamp, round.ending_timestamp, round.ended, round.failed, round.stage_code, round.txid, round.unsigned_tx, round.congestion_tree, round.forfeit_txs, round.connectors, round.connector_address, round.dust_amount, round.version, round.swept, payment.id, receiver.payment_id, receiver.pubkey, receiver.amount, receiver.onchain_address, vtxo.txid, vtxo.vout, vtxo.pubkey, vtxo.amount, vtxo.pool_tx, vtxo.spent_by, vtxo.spent, vtxo.redeemed, vtxo.swept, vtxo.expire_at, vtxo.payment_id
FROM round 
LEFT OUTER JOIN payment ON round.txid=payment.txid 
LEFT OUTER JOIN receiver ON payment.id=receiver.payment_id
LEFT OUTER JOIN vtxo ON payment.id=vtxo.payment_id
WHERE round.swept = true AND round.failed = false AND round.ended = true;
`

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

type roundRow struct {
	id                *string
	startingTimestamp *int64
	endingTimestamp   *int64
	ended             *bool
	failed            *bool
	stageCode         *domain.RoundStage
	txid              *string
	unsignedTx        *string
	forfeitTxs        *string
	congestionTree    *string
	connectors        *string
	connectorAddress  *string
	dustAmount        *uint64
	version           *uint
	swept             *bool
}

type roundRepository struct {
	db *sql.DB
}

func NewRoundRepository(args ...interface{}) (dbtypes.RoundStore, error) {
	db, ok := args[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot create new SQLite Round repository: invalid args")
	}

	return newRoundRepository(db)
}

func newRoundRepository(db *sql.DB) (dbtypes.RoundStore, error) {
	if _, err := db.Exec(createRoundTable); err != nil {
		return nil, err
	}

	if _, err := db.Exec(createPaymentTable); err != nil {
		return nil, err
	}

	if _, err := db.Exec(createReceiverTable); err != nil {
		return nil, err
	}

	return &roundRepository{
		db: db,
	}, nil
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

	var congestionTreeJSON string

	if round.CongestionTree != nil {
		writer := new(bytes.Buffer)

		if err := round.CongestionTree.Encode(writer); err != nil {
			return err
		}

		congestionTreeJSON = writer.String()
	}

	connectorsCSV := encodeStrings(round.Connectors)
	forfeitsCSV := encodeStrings(round.ForfeitTxs)

	_, err = stmt.Exec(
		round.Id,
		round.StartingTimestamp,
		round.EndingTimestamp,
		round.Stage.Ended,
		round.Stage.Failed,
		round.Stage.Code,
		round.Txid,
		round.UnsignedTx,
		congestionTreeJSON,
		forfeitsCSV,
		connectorsCSV,
		round.ConnectorAddress,
		round.DustAmount,
		round.Version,
		round.Swept,
	)
	if err != nil {
		return err
	}

	if round.Payments != nil {
		for _, payment := range round.Payments {
			stmt, err := tx.Prepare(upsertPayment)
			if err != nil {
				return err
			}

			defer stmt.Close()

			_, err = stmt.Exec(payment.Id, round.Txid)
			if err != nil {
				return err
			}

			stmt, err = tx.Prepare(upsertReceiver)
			if err != nil {
				return err
			}

			for _, receiver := range payment.Receivers {
				_, err := stmt.Exec(payment.Id, receiver.Pubkey, receiver.Amount, receiver.OnchainAddress)
				if err != nil {
					return err
				}
			}

			stmt, err = tx.Prepare(updateVtxoPaymentId)
			if err != nil {
				return err
			}

			defer stmt.Close()

			for _, input := range payment.Inputs {
				_, err := stmt.Exec(payment.Id, input.Txid, input.VOut)
				if err != nil {
					return err
				}
			}
		}
	}

	return tx.Commit()
}

func (r *roundRepository) GetCurrentRound(ctx context.Context) (*domain.Round, error) {
	stmt, err := r.db.Prepare(selectCurrentRound)
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

	if len(rounds) == 0 {
		return nil, errors.New("no current round")
	}

	return rounds[0], nil
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

func encodeStrings(strs []string) string {
	return strings.Join(strs, ",")
}

func decodeStrings(str string) []string {
	return strings.Split(str, ",")
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

		if err := rows.Scan(
			&roundRow.id,
			&roundRow.startingTimestamp,
			&roundRow.endingTimestamp,
			&roundRow.ended,
			&roundRow.failed,
			&roundRow.stageCode,
			&roundRow.txid,
			&roundRow.unsignedTx,
			&roundRow.congestionTree,
			&roundRow.forfeitTxs,
			&roundRow.connectors,
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
			var congestionTree tree.CongestionTree

			_ = congestionTree.Decode(strings.NewReader(*roundRow.congestionTree))

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
				CongestionTree:   congestionTree,
				ForfeitTxs:       decodeStrings(*roundRow.forfeitTxs),
				Connectors:       decodeStrings(*roundRow.connectors),
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

		rounds[*roundRow.id] = round
	}

	var result []*domain.Round

	for _, round := range rounds {
		result = append(result, round)
	}

	return result, nil
}
