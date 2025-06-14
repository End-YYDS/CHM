-- Add down migration script here
DROP INDEX IF EXISTS idx_crl_entries_revoked_at;
DROP INDEX IF EXISTS idx_crl_entries_cert_serial;
DROP INDEX IF EXISTS idx_certs_status;
DROP INDEX IF EXISTS idx_certs_expiration;
DROP INDEX IF EXISTS idx_certs_issuer;
DROP INDEX IF EXISTS idx_certs_subject_cn;
DROP TABLE IF EXISTS crl_entries;
DROP TABLE IF EXISTS certs;
