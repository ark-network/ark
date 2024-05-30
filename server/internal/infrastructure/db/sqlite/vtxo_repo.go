package sqlitedb

import (
	"context"
	"database/sql"

	"github.com/ark-network/ark/internal/core/domain"
)

const (
	createVtxoTable = `
CREATE TABLE IF NOT EXISTS vtxo (
	txid TEXT NOT NULL PRIMARY KEY,
	vout INTEGER NOT NULL,
	pubkey TEXT NOT NULL,
	amount INTEGER NOT NULL,
	pool_tx TEXT NOT NULL,
	spent_by TEXT NOT NULL,
	spent BOOLEAN NOT NULL,
	redeemed BOOLEAN NOT NULL,
	swept BOOLEAN NOT NULL,
	expire_at INTEGER NOT NULL,
	payment_id TEXT,
	FOREIGN KEY (payment_id) REFERENCES payment(id)
);
`

	insertVtxos = `
INSERT INTO vtxo (txid, vout, pubkey, amount, pool_tx, spent_by, spent, redeemed, swept, expire_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`

	selectSweepableVtxos = `
SELECT * FROM vtxo WHERE redeemed = false AND swept = false
`

	selectNotRedeemedVtxos = `
SELECT * FROM vtxo WHERE redeemed = false
`

	selectNotRedeemedVtxosWithPubkey = `
SELECT * FROM vtxo WHERE redeemed = false AND pubkey = ?
`

	selectVtxosByTxids = `
SELECT * FROM vtxo WHERE txid IN (?)
`

	selectVtxosByPoolTxid = `
SELECT * FROM vtxo WHERE pool_tx = ?
`

	markVtxoAsRedeemed = `
UPDATE vtxo SET redeemed = true WHERE txid = ? AND vout = ?
`

	markVtxoAsSwept = `
UPDATE vtxo SET swept = true WHERE txid = ? AND vout = ?
`

	markVtxoAsSpent = `
UPDATE vtxo SET spent = true, spent_by = ? WHERE txid = ? AND vout = ?
`

	updateVtxoExpireAt = `
UPDATE vtxo SET expire_at = ? WHERE txid = ? AND vout = ?
`
)

type vtxoRow struct {
	txid      *string
	vout      *uint32
	pubkey    *string
	amount    *uint64
	poolTx    *string
	spentBy   *string
	spent     *bool
	redeemed  *bool
	swept     *bool
	expireAt  *int64
	paymentID *string
}

type vxtoRepository struct {
	db *sql.DB
}

func NewVtxoRepository(db *sql.DB) (domain.VtxoRepository, error) {
	_, err := db.Exec(createVtxoTable)
	if err != nil {
		return nil, err
	}

	return &vxtoRepository{db}, nil
}

func (v *vxtoRepository) AddVtxos(ctx context.Context, vtxos []domain.Vtxo) error {
	tx, err := v.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(insertVtxos)
	if err != nil {
		return err
	}

	for _, vtxo := range vtxos {
		_, err := stmt.Exec(
			vtxo.Txid,
			vtxo.VOut,
			vtxo.Pubkey,
			vtxo.Amount,
			vtxo.PoolTx,
			vtxo.SpentBy,
			vtxo.Spent,
			vtxo.Redeemed,
			vtxo.Swept,
			vtxo.ExpireAt,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (v *vxtoRepository) GetAllSweepableVtxos(ctx context.Context) ([]domain.Vtxo, error) {
	rows, err := v.db.Query(selectSweepableVtxos)
	if err != nil {
		return nil, err
	}

	return readRows(rows)
}

func (v *vxtoRepository) GetAllVtxos(ctx context.Context, pubkey string) ([]domain.Vtxo, []domain.Vtxo, error) {
	withPubkey := len(pubkey) > 0

	var rows *sql.Rows
	var err error

	if withPubkey {
		rows, err = v.db.Query(selectNotRedeemedVtxosWithPubkey, pubkey)
	} else {
		rows, err = v.db.Query(selectNotRedeemedVtxos)
	}
	if err != nil {
		return nil, nil, err
	}

	vtxos, err := readRows(rows)
	if err != nil {
		return nil, nil, err
	}

	unspentVtxos := make([]domain.Vtxo, 0)
	spentVtxos := make([]domain.Vtxo, 0)

	for _, vtxo := range vtxos {
		if vtxo.Spent {
			spentVtxos = append(spentVtxos, vtxo)
		} else {
			unspentVtxos = append(unspentVtxos, vtxo)
		}
	}

	return unspentVtxos, spentVtxos, nil
}

func (v *vxtoRepository) GetVtxos(ctx context.Context, vtxos []domain.VtxoKey) ([]domain.Vtxo, error) {
	txids := ""
	for i, vtxo := range vtxos {
		txids += vtxo.Txid
		if i < len(vtxos)-1 {
			txids += ","
		}
	}

	rows, err := v.db.Query(selectVtxosByTxids, txids)
	if err != nil {
		return nil, err
	}

	return readRows(rows)
}

func (v *vxtoRepository) GetVtxosForRound(ctx context.Context, txid string) ([]domain.Vtxo, error) {
	rows, err := v.db.Query(selectVtxosByPoolTxid, txid)
	if err != nil {
		return nil, err
	}

	return readRows(rows)
}

func (v *vxtoRepository) RedeemVtxos(ctx context.Context, vtxos []domain.VtxoKey) error {
	tx, err := v.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(markVtxoAsRedeemed)
	if err != nil {
		return err
	}

	for _, vtxo := range vtxos {
		_, err := stmt.Exec(vtxo.Txid, vtxo.VOut)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (v *vxtoRepository) SpendVtxos(ctx context.Context, vtxos []domain.VtxoKey, txid string) error {
	tx, err := v.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(markVtxoAsSpent)
	if err != nil {
		return err
	}

	for _, vtxo := range vtxos {
		_, err := stmt.Exec(txid, vtxo.Txid, vtxo.VOut)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (v *vxtoRepository) SweepVtxos(ctx context.Context, vtxos []domain.VtxoKey) error {
	tx, err := v.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(markVtxoAsSwept)
	if err != nil {
		return err
	}

	for _, vtxo := range vtxos {
		_, err := stmt.Exec(vtxo.Txid, vtxo.VOut)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (v *vxtoRepository) UpdateExpireAt(ctx context.Context, vtxos []domain.VtxoKey, expireAt int64) error {
	tx, err := v.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(updateVtxoExpireAt)
	if err != nil {
		return err
	}

	for _, vtxo := range vtxos {
		_, err := stmt.Exec(expireAt, vtxo.Txid, vtxo.VOut)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func rowToVtxo(row vtxoRow) domain.Vtxo {
	return domain.Vtxo{
		VtxoKey: domain.VtxoKey{
			Txid: *row.txid,
			VOut: *row.vout,
		},
		Receiver: domain.Receiver{
			Pubkey: *row.pubkey,
			Amount: *row.amount,
		},
		PoolTx:   *row.poolTx,
		SpentBy:  *row.spentBy,
		Spent:    *row.spent,
		Redeemed: *row.redeemed,
		Swept:    *row.swept,
		ExpireAt: *row.expireAt,
	}
}

func readRows(rows *sql.Rows) ([]domain.Vtxo, error) {
	defer rows.Close()
	vtxos := make([]domain.Vtxo, 0)

	for rows.Next() {
		var row vtxoRow
		if err := rows.Scan(
			&row.txid,
			&row.vout,
			&row.pubkey,
			&row.amount,
			&row.poolTx,
			&row.spentBy,
			&row.spent,
			&row.redeemed,
			&row.swept,
			&row.expireAt,
			&row.paymentID,
		); err != nil {
			return nil, err
		}

		vtxos = append(vtxos, rowToVtxo(row))
	}

	return vtxos, nil
}
