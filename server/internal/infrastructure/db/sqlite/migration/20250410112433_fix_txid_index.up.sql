DROP INDEX IF EXISTS idx_round_txid;

CREATE INDEX IF NOT EXISTS idx_round_txid ON round(txid);