CREATE TABLE IF NOT EXISTS new_receiver (
    payment_id TEXT NOT NULL,
    descriptor TEXT NOT NULL,
    amount INTEGER NOT NULL,
    onchain_address TEXT NOT NULL,
    FOREIGN KEY (payment_id) REFERENCES payment(id),
    PRIMARY KEY (payment_id, descriptor)
);

INSERT INTO new_receiver SELECT * FROM receiver;

DROP VIEW payment_vtxo_vw;
DROP VIEW payment_receiver_vw;
DROP TABLE receiver;
ALTER TABLE new_receiver RENAME TO receiver;

ALTER TABLE vtxo ADD COLUMN descriptor TEXT;
ALTER TABLE vtxo ADD COLUMN signer_pubkey TEXT;
ALTER TABLE vtxo DROP COLUMN pubkey;

CREATE VIEW payment_vtxo_vw AS SELECT vtxo.*
FROM payment
LEFT OUTER JOIN vtxo
ON payment.id=vtxo.payment_id;

CREATE VIEW payment_receiver_vw AS SELECT receiver.*
FROM payment
LEFT OUTER JOIN receiver
ON payment.id=receiver.payment_id;