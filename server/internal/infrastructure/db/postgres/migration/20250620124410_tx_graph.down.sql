DROP VIEW IF EXISTS round_commitment_tx_vw;
DROP VIEW IF EXISTS round_tx_vw;

ALTER TABLE tx DROP COLUMN children JSONB;

ALTER TABLE tx ADD COLUMN tree_level INTEGER;
ALTER TABLE tx ADD COLUMN parent_txid VARCHAR;
ALTER TABLE tx ADD COLUMN is_leaf BOOLEAN;

CREATE VIEW round_tx_vw AS
SELECT tx.*
FROM round
LEFT OUTER JOIN tx
ON round.id=tx.round_id;

CREATE VIEW round_commitment_tx_vw AS
SELECT round.*, tx.*
FROM round
INNER JOIN tx
ON round.id=tx.round_id AND tx.type='commitment';