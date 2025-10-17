-- Add up migration script here
CREATE TABLE IF NOT EXISTS id_alloc(
  kind TEXT PRIMARY KEY,
  next INTEGER NOT NULL
);
