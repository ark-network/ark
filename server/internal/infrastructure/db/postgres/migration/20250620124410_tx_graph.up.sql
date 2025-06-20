DROP VIEW IF EXISTS round_commitment_tx_vw;
DROP VIEW IF EXISTS round_tx_vw;

ALTER TABLE tx DROP COLUMN tree_level;
ALTER TABLE tx DROP COLUMN parent_txid;
ALTER TABLE tx DROP COLUMN is_leaf;

ALTER TABLE tx ADD COLUMN children JSONB;

CREATE VIEW round_commitment_tx_vw AS
SELECT round.*, tx.*
FROM round
INNER JOIN tx
ON round.id = tx.round_id AND tx.type = 'commitment';

CREATE VIEW round_tx_vw AS
SELECT tx.*
FROM round
LEFT OUTER JOIN tx
ON round.id = tx.round_id;