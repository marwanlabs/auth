-- 0002: core authentication store.
DO $$
BEGIN
    CREATE TABLE users (
        id            TEXT PRIMARY KEY,
        email         TEXT NOT NULL UNIQUE,
        google_id     TEXT NOT NULL DEFAULT '',
        password_hash TEXT NOT NULL DEFAULT '',
        role          TEXT NOT NULL,
        disabled      BOOLEAN NOT NULL DEFAULT false,
        created_at    TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE sessions (
        id         TEXT PRIMARY KEY,
        user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        user_agent TEXT NOT NULL,
        ip         TEXT NOT NULL
    );
    CREATE INDEX sessions_user_id_idx ON sessions (user_id);
    CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
    CREATE TABLE reset_tokens (
        token_hash TEXT PRIMARY KEY,
        user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX reset_tokens_expires_at_idx ON reset_tokens (expires_at);
    CREATE TABLE social_identities (
        id         TEXT PRIMARY KEY,
        provider   TEXT NOT NULL,
        subject    TEXT NOT NULL,
        user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL,
        UNIQUE (provider, subject)
    );
    CREATE TABLE provider_settings (
        provider TEXT PRIMARY KEY,
        enabled  BOOLEAN NOT NULL
    );
END
$$;
