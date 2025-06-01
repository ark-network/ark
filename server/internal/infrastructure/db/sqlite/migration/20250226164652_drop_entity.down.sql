CREATE TABLE IF NOT EXISTS entity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nostr_recipient TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS entity_vtxo (
    entity_id INTEGER NOT NULL,
    vtxo_txid TEXT NOT NULL,
    vtxo_vout INTEGER NOT NULL,
    FOREIGN KEY (entity_id) REFERENCES entity(id),
    PRIMARY KEY (entity_id, vtxo_txid, vtxo_vout)
);

CREATE VIEW entity_vw AS SELECT entity.id, entity.nostr_recipient, entity_vtxo.vtxo_txid, entity_vtxo.vtxo_vout
FROM entity
LEFT OUTER JOIN entity_vtxo
ON entity.id=entity_vtxo.entity_id;
