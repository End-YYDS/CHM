-- Add up migration script here
CREATE EXTENSION IF NOT EXISTS citext;
CREATE TABLE hosts (
    id uuid PRIMARY KEY,
    hostname CITEXT NOT NULL,
    ip inet NOT NULL
);
