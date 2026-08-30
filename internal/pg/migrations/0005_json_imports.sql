-- 0005: singleton ledger for the one-time JSON to PostgreSQL import.
CREATE TABLE json_imports (
    id            BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    source_path   TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    imported_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
