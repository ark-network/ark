ALTER TABLE vtxo DROP COLUMN addr;
ALTER TABLE vtxo ADD COLUMN descriptor TEXT;

ALTER TABLE receiver DROP COLUMN addr;
ALTER TABLE receiver ADD COLUMN onchain_address TEXT;
ALTER TABLE receiver ADD COLUMN descriptor TEXT;

DROP VIEW payment_vtxo_vw;
DROP VIEW payment_receiver_vw;

CREATE VIEW payment_vtxo_vw AS SELECT vtxo.*
FROM payment
LEFT OUTER JOIN vtxo
ON payment.id=vtxo.payment_id;

CREATE VIEW payment_receiver_vw AS SELECT receiver.*
FROM payment
LEFT OUTER JOIN receiver
ON payment.id=receiver.payment_id;