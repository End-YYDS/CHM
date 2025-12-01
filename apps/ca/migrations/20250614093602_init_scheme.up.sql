-- Add up migration script here
-- 建立 certs 表
CREATE TABLE IF NOT EXISTS certs (
    serial       TEXT      PRIMARY KEY,          -- 憑證序號 (hex)
    subject_cn   TEXT      NOT NULL,             -- Common Name
    subject_dn   TEXT      NOT NULL,             -- 完整 Subject DN
    issuer       TEXT      NOT NULL,             -- 完整 Issuer DN
    issued_date  TEXT      NOT NULL,             -- 存成 ISO8601 字串 (e.g. "2025-06-01T12:34:56Z")
    expiration   TEXT      NOT NULL,             -- 同上
    thumbprint   TEXT      NOT NULL UNIQUE,
    status       TEXT      NOT NULL DEFAULT 'valid',
    cert_der     BLOB      NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_certs_subject_cn
    ON certs(subject_cn);
CREATE INDEX IF NOT EXISTS idx_certs_issuer
    ON certs(issuer);
CREATE INDEX IF NOT EXISTS idx_certs_expiration
    ON certs(expiration);
CREATE INDEX IF NOT EXISTS idx_certs_status
    ON certs(status);

CREATE TABLE IF NOT EXISTS crl_entries (
    id             INTEGER   PRIMARY KEY AUTOINCREMENT,
    cert_serial    TEXT      NOT NULL,
    revoked_at     TEXT      NOT NULL,            -- 同樣以 ISO8601 字串儲存
    reason         TEXT      ,
    FOREIGN KEY (cert_serial) REFERENCES certs(serial) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_crl_entries_cert_serial
    ON crl_entries(cert_serial);
CREATE INDEX IF NOT EXISTS idx_crl_entries_revoked_at
    ON crl_entries(revoked_at);
