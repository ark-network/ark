ALTER TABLE vtxo ADD COLUMN pending BOOLEAN NOT NULL;

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