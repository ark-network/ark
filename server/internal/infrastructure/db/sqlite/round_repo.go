package sqlitedb

import (
	"bytes"
	"context"
	"database/sql"
	"strings"

	"github.com/ark-network/ark/internal/core/domain"
)

const (
	createReceiverTable = `
CREATE TABLE IF NOT EXISTS receiver (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	payment_id TEXT NOT NULL,
	pubkey TEXT NOT NULL,
	amount INTEGER NOT NULL,
	onchain_address TEXT NOT NULL,
	FOREIGN KEY (payment_id) REFERENCES payment(id)
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
UPSERT INTO round (
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
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`

	upsertPayment = `
UPSERT INTO payment (id, txid) VALUES (?, ?);
`

	upserReceiver = `
UPSERT INTO receiver (payment_id, pubkey, amount, onchain_address) VALUES (?, ?, ?, ?)
`

	updateVtxoPaymentId = `
UPDATE vtxo SET payment_id = ? WHERE txid = ? AND vout = ? ON CONFLICT(txid, vout) DO NOTHING;
`

	selectCurrentRound = `
SELECT * FROM round WHERE ended = false AND failed = false;
`
)

type receiverRow struct {
	paymentId      string
	pubkey         string
	amount         uint64
	onchainAddress string
}

type paymentRow struct {
	id        string
	receivers []receiverRow
	inputs    []vtxoRow
}

type roundRow struct {
	id                string
	startingTimestamp int64
	endingTimestamp   int64
	ended             bool
	failed            bool
	stageCode         domain.RoundStage
	txid              string
	payments          []paymentRow
	unsignedTx        string
	forfeitTxs        []string
	congestionTree    string
	connectors        []string
	connectorAddress  string
	dustAmount        uint64
	version           uint
	swept             bool
}

type roundRepository struct {
	db *sql.DB
}

func NewRoundRepository(db *sql.DB) (domain.RoundRepository, error) {
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

func (r *roundRepository) AddOrUpdateRound(ctx context.Context, round domain.Round) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(upsertRound)
	if err != nil {
		return err
	}

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

	for _, payment := range round.Payments {
		stmt, err := tx.Prepare(upsertPayment)
		if err != nil {
			return err
		}

		_, err = stmt.Exec(payment.Id, round.Txid)
		if err != nil {
			return err
		}

		stmt, err = tx.Prepare(upserReceiver)
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

		for _, input := range payment.Inputs {
			_, err := stmt.Exec(payment.Id, input.Txid, input.VOut)
			if err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

func (r *roundRepository) GetCurrentRound(ctx context.Context) (*domain.Round, error) {
	panic("unimplemented")
}

// GetRoundWithId implements domain.RoundRepository.
func (r *roundRepository) GetRoundWithId(ctx context.Context, id string) (*domain.Round, error) {
	panic("unimplemented")
}

// GetRoundWithTxid implements domain.RoundRepository.
func (r *roundRepository) GetRoundWithTxid(ctx context.Context, txid string) (*domain.Round, error) {
	panic("unimplemented")
}

// GetSweepableRounds implements domain.RoundRepository.
func (r *roundRepository) GetSweepableRounds(ctx context.Context) ([]domain.Round, error) {
	panic("unimplemented")
}

func encodeStrings(strs []string) string {
	return strings.Join(strs, ",")
}

func decodeStrings(str string) []string {
	return strings.Split(str, ",")
}
