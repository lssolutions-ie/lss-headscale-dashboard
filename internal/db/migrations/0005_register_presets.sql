-- Saved Register Node form presets. values_json holds the form's field/value
-- map verbatim; this keeps the schema stable as the form gains/loses flags.
CREATE TABLE register_presets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL COLLATE NOCASE,
    values_json TEXT    NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX idx_register_presets_name ON register_presets(name);
