ALTER TABLE webauthn_credentials ADD COLUMN backup_eligible INTEGER NOT NULL DEFAULT 0;
ALTER TABLE webauthn_credentials ADD COLUMN backup_state    INTEGER NOT NULL DEFAULT 0;
