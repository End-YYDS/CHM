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
