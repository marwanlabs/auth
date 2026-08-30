-- 0004: short-lived provider-bound OAuth transactions.
DO $$
BEGIN
    CREATE TABLE oauth_transactions (
        id            TEXT PRIMARY KEY,
        provider      TEXT NOT NULL,
        pkce_verifier TEXT NOT NULL,
        created_at    TIMESTAMPTZ NOT NULL,
        expires_at    TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX oauth_transactions_expires_at_idx ON oauth_transactions (expires_at);
END
$$;
