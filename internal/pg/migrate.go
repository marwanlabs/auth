package pg

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// advisoryLockID serializes migration runs across server instances so two
// processes can never race a schema change. Value is the ASCII bytes of
// "AUTHSERV" as a bigint.
const advisoryLockID = 0x4155544853455256

// createMigrationsTable bootstraps the version ledger. It lives in code
// rather than a migration so the ledger can be created even before the first
// migration exists.
const createMigrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    BIGINT PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// migration is one versioned schema change. Each migration file must contain
// exactly one SQL statement, because it is executed on a single prepared
// statement.
type migration struct {
	version int64
	name    string
	stmt    string
}

var migrationNameRE = regexp.MustCompile(`^(\d+)_(.+)\.sql$`)

// migrations loads and validates the embedded, versioned migration files,
// returning them in strict forward order so they can be applied
// repeatably.
func migrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	var list []migration
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		parts := migrationNameRE.FindStringSubmatch(entry.Name())
		if parts == nil {
			return nil, fmt.Errorf("migration file %q does not match NNNN_name.sql", entry.Name())
		}
		version, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing version from migration file %q: %w", entry.Name(), err)
		}
		raw, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, err
		}
		stmt := strings.TrimSpace(string(raw))
		if stmt == "" {
			return nil, fmt.Errorf("migration %d (%s) is empty", version, entry.Name())
		}
		list = append(list, migration{version: version, name: parts[2], stmt: stmt})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].version < list[j].version })
	for i, m := range list {
		if (i == 0 && m.version != 1) || (i > 0 && m.version <= list[i-1].version) {
			return nil, fmt.Errorf("migration versions must be strictly increasing; version %d is out of order", m.version)
		}
	}
	if len(list) == 0 {
		return nil, errors.New("no migrations embedded")
	}
	return list, nil
}

// Migrate applies every pending versioned schema migration and returns the
// latest applied version. It runs on a single pinned connection under a
// cluster-wide advisory lock, so repeated runs are safe no-ops and concurrent
// server instances serialize their schema changes.
func Migrate(ctx context.Context, db *sql.DB) (int64, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return migratePinned(ctx, conn)
}

func migratePinned(ctx context.Context, conn *sql.Conn) (int64, error) {
	if _, err := conn.ExecContext(ctx, createMigrationsTable); err != nil {
		return 0, fmt.Errorf("creating schema_migrations table: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", advisoryLockID); err != nil {
		return 0, fmt.Errorf("acquiring schema migration lock: %w", err)
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", advisoryLockID)

	pending, err := migrations()
	if err != nil {
		return 0, err
	}
	latest := pending[len(pending)-1].version

	applied, err := appliedVersions(ctx, conn)
	if err != nil {
		return 0, err
	}
	var maxApplied int64
	for version := range applied {
		if version > maxApplied {
			maxApplied = version
		}
	}
	if maxApplied > latest {
		return 0, fmt.Errorf("database schema version %d is newer than this binary supports (%d); refusing to proceed", maxApplied, latest)
	}

	for _, m := range pending {
		if applied[m.version] {
			continue
		}
		tx, err := conn.BeginTx(ctx, &sql.TxOptions{})
		if err != nil {
			return 0, fmt.Errorf("starting migration %d (%s): %w", m.version, m.name, err)
		}
		if _, err := tx.ExecContext(ctx, m.stmt); err != nil {
			_ = tx.Rollback()
			return 0, fmt.Errorf("applying migration %d (%s): %w", m.version, m.name, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)", m.version, m.name); err != nil {
			_ = tx.Rollback()
			return 0, fmt.Errorf("recording migration %d (%s): %w", m.version, m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("committing migration %d (%s): %w", m.version, m.name, err)
		}
	}
	return latest, nil
}

func appliedVersions(ctx context.Context, conn *sql.Conn) (map[int64]bool, error) {
	rows, err := conn.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("reading applied schema migrations: %w", err)
	}
	defer rows.Close()
	applied := make(map[int64]bool)
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return applied, nil
}
