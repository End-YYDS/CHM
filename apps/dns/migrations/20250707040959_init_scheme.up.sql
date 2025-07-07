-- Add up migration script here
CREATE TABLE hosts (
    id uuid PRIMARY KEY,
    hostname TEXT NOT NULL,
    ip inet NOT NULL
);
