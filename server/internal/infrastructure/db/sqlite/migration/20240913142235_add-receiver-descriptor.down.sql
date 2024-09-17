CREATE TABLE IF NOT EXISTS old_receiver (
    payment_id TEXT NOT NULL,
    pubkey TEXT NOT NULL,
    amount INTEGER NOT NULL,
    onchain_address TEXT NOT NULL,
    FOREIGN KEY (payment_id) REFERENCES payment(id),
    PRIMARY KEY (payment_id, pubkey)
);

INSERT INTO old_receiver SELECT * FROM receiver;

DROP TABLE receiver;

ALTER TABLE old_receiver RENAME TO receiver;

ALTER TABLE vtxo DROP COLUMN descriptor;
ALTER TABLE vtxo ADD COLUMN pubkey TEXT NOT NULL;
