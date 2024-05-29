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
	payment_id TEXT NOT NULL,
	FOREIGN KEY (payment_id) REFERENCES payment(id)
);
`

	insertVtxos = `
INSERT INTO vtxo (txid, vout, pubkey, amount, pool_tx, spent_by, spent, redeemed, swept, expire_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`

	selectSweepableVtxos = `
SELECT * FROM vtxo WHERE spent = false AND redeemed = false AND swept = false
`

	selectNotRedeemedVtxosSpent = `
SELECT * FROM vtxo WHERE redeemed = false AND spent = true
`

	selectNotRedeemedVtxosUnspent = `
SELECT * FROM vtxo WHERE redeemed = false AND spent = false
`

	selectNotRedeemedVtxosSpentWithPubkey = `
SELECT * FROM vtxo WHERE redeemed = false AND spent = true AND pubkey = ?
`

	selectNotRedeemedVtxosUnspentWithPubkey = `
SELECT * FROM vtxo WHERE redeemed = false AND spent = false AND pubkey = ?
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
	Txid     string `json:"txid"`
	Vout     uint32 `json:"vout"`
	Pubkey   string `json:"pubkey"`
	Amount   uint64 `json:"amount"`
	PoolTx   string `json:"pool_tx"`
	SpentBy  string `json:"spent_by"`
	Spent    bool   `json:"spent"`
	Redeemed bool   `json:"redeemed"`
	Swept    bool   `json:"swept"`
	ExpireAt int64  `json:"expire_at"`
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
	defer rows.Close()

	return readRows(rows)
}

// GetAllVtxos implements domain.VtxoRepository.
func (v *vxtoRepository) GetAllVtxos(ctx context.Context, pubkey string) ([]domain.Vtxo, []domain.Vtxo, error) {
	withPubkey := len(pubkey) > 0

	var rows *sql.Rows
	var err error

	if withPubkey {
		rows, err = v.db.Query(selectNotRedeemedVtxosSpentWithPubkey, pubkey)
	} else {
		rows, err = v.db.Query(selectNotRedeemedVtxosSpent)
	}
	if err != nil {
		return nil, nil, err
	}

	spentVtxos, err := readRows(rows)
	if err != nil {
		return nil, nil, err
	}

	if withPubkey {
		rows, err = v.db.Query(selectNotRedeemedVtxosUnspentWithPubkey, pubkey)
	} else {
		rows, err = v.db.Query(selectNotRedeemedVtxosUnspent)
	}
	if err != nil {
		return nil, nil, err
	}

	unspentVtxos, err := readRows(rows)
	if err != nil {
		return nil, nil, err
	}

	return unspentVtxos, spentVtxos, nil
}

func (v *vxtoRepository) GetVtxos(ctx context.Context, vtxos []domain.VtxoKey) ([]domain.Vtxo, error) {
	txids := make([]string, 0, len(vtxos))
	for _, vtxo := range vtxos {
		txids = append(txids, vtxo.Txid)
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
			Txid: row.Txid,
			VOut: row.Vout,
		},
		Receiver: domain.Receiver{
			Pubkey: row.Pubkey,
			Amount: row.Amount,
		},
		PoolTx:   row.PoolTx,
		SpentBy:  row.SpentBy,
		Spent:    row.Spent,
		Redeemed: row.Redeemed,
		Swept:    row.Swept,
		ExpireAt: row.ExpireAt,
	}
}

func readRows(rows *sql.Rows) ([]domain.Vtxo, error) {
	var vtxos []domain.Vtxo
	for rows.Next() {
		var row vtxoRow
		if err := rows.Scan(
			&row.Txid,
			&row.Vout,
			&row.Pubkey,
			&row.Amount,
			&row.PoolTx,
			&row.SpentBy,
			&row.Spent,
			&row.Redeemed,
			&row.Swept,
			&row.ExpireAt,
		); err != nil {
			return nil, err
		}

		vtxos = append(vtxos, rowToVtxo(row))
	}

	return vtxos, nil
}
