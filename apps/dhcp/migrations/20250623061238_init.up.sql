-- Add up migration script here

PRAGMA foreign_keys = ON;

CREATE TABLE zones (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL UNIQUE,
    network      TEXT    NOT NULL,
    broadcast    TEXT    NOT NULL,
    subnet_mask  TEXT    NOT NULL,
    vni          INTEGER NOT NULL UNIQUE
);

CREATE TABLE zone_pcs (
    zone_id INTEGER NOT NULL,
    pc_uuid TEXT NOT NULL,
    PRIMARY KEY (zone_id, pc_uuid),
    FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX idx_zone_pcs_pc_uuid ON zone_pcs(pc_uuid);

CREATE TABLE ip_pools (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    zone_id  INTEGER NOT NULL,
    ip       TEXT    NOT NULL,
    FOREIGN KEY (zone_id)
        REFERENCES zones(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    UNIQUE (zone_id, ip)
);

CREATE INDEX idx_ip_pools_zone_id ON ip_pools(zone_id);
