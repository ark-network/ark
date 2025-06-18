ALTER TABLE tx DROP COLUMN tree_level;
ALTER TABLE tx DROP COLUMN parent_txid;
ALTER TABLE tx DROP COLUMN is_leaf;

ALTER TABLE tx ADD COLUMN children TEXT;

DROP VIEW IF EXISTS round_tx_vw;
CREATE VIEW IF NOT EXISTS round_tx_vw AS
SELECT tx.*
FROM round
LEFT OUTER JOIN tx
ON round.id=tx.round_id;