-- 0001: PostgreSQL runtime foundation.
--
-- Bootstraps the minimal schema the auth service runtime relies on. The
-- concrete store tables (users, sessions, audit events, and friends) arrive
-- with the PostgreSQL store implementation and intentionally do not exist
-- yet.
--
-- app_metadata is a service-owned key/value bucket for runtime metadata
-- such as a service instance marker or maintenance flags.
CREATE TABLE app_metadata (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);