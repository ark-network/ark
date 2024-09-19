/* Transaction */
-- name: SelectAllTransactions :many
SELECT * FROM txs;

-- name: SelectBoardingTransaction :many
SELECT * FROM txs WHERE boarding_txid <> '';


/* Vtxo */

-- name: SelectAllVtxos :many
SELECT * FROM vtxo;