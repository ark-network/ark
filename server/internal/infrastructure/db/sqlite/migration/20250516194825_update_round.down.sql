ALTER TABLE round ADD COLUMN dust_amount INTEGER NOT NULL;
ALTER TABLE round ADD COLUMN unsigned_tx TEXT NOT NULL;
ALTER TABLE round DROP COLUMN vtxo_tree_expiration;

DROP TABLE IF EXISTS offchain_tx;
DROP TABLE IF EXISTS virtual_tx;