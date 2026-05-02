-- Tracks failed login attempts per (username, ip) for rate-limit + lockout.
CREATE TABLE auth_failures (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT    NOT NULL,
    ip        TEXT    NOT NULL,
    failed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_auth_failures_lookup ON auth_failures(username, ip, failed_at);
CREATE INDEX idx_auth_failures_age    ON auth_failures(failed_at);
