DROP INDEX IF EXISTS idx_round_txid;

CREATE UNIQUE INDEX IF NOT EXISTS idx_round_txid ON round(txid);