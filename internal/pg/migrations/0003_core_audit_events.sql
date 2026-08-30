-- 0003: authentication and administration audit events.
DO $$
BEGIN
    CREATE TABLE audit_events (
        event_order BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        id          TEXT NOT NULL UNIQUE,
        type        TEXT NOT NULL,
        outcome     TEXT NOT NULL,
        occurred_at TIMESTAMPTZ NOT NULL,
        actor_id    TEXT NOT NULL DEFAULT '',
        actor_email TEXT NOT NULL DEFAULT '',
        target      TEXT NOT NULL DEFAULT '',
        client_ip   TEXT NOT NULL DEFAULT '',
        user_agent  TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX audit_events_chronological_idx ON audit_events (occurred_at, event_order);
END
$$;
