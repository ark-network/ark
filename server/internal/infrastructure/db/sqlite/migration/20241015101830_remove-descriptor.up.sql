ALTER TABLE vtxo DROP COLUMN descriptor;
ALTER TABLE vtxo ADD COLUMN addr TEXT;

DROP TABLE IF EXISTS receiver;

CREATE TABLE IF NOT EXISTS receiver (
    payment_id TEXT NOT NULL,
    addr TEXT NOT NULL,
    amount INTEGER NOT NULL,
    FOREIGN KEY (payment_id) REFERENCES payment(id),
    PRIMARY KEY (payment_id, addr)
);

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