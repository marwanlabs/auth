package pg

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrImportNotVerified indicates that PostgreSQL has not received a complete,
// committed JSON import and is therefore not safe for normal server use.
var ErrImportNotVerified = errors.New("complete JSON import has not been verified")

// VerifyJSONImport verifies that the database has the complete schema shipped
// by this binary and has a committed import marker. The marker is written by
// ImportJSON only after all core auth, audit, and OAuth records are committed.
func VerifyJSONImport(ctx context.Context, db *sql.DB) error {
	shipped, err := migrations()
	if err != nil {
		return fmt.Errorf("load embedded migrations: %w", err)
	}

	rows, err := db.QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("read schema migrations: %w", err)
	}
	defer rows.Close()
	var applied []int64
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			return fmt.Errorf("scan schema migration: %w", err)
		}
		applied = append(applied, version)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read schema migrations: %w", err)
	}
	if err := verifyMigrationVersions(shipped, applied); err != nil {
		return err
	}

	var sourcePath, digest string
	if err := db.QueryRowContext(ctx, `SELECT source_path, source_sha256 FROM json_imports WHERE id = true`).Scan(&sourcePath, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrImportNotVerified
		}
		return fmt.Errorf("read JSON import marker: %w", err)
	}
	if sourcePath == "" || len(digest) != 64 {
		return ErrImportNotVerified
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return ErrImportNotVerified
	}
	return nil
}

func verifyMigrationVersions(shipped []migration, applied []int64) error {
	if len(applied) != len(shipped) {
		return fmt.Errorf("schema migrations incomplete: applied %d of %d", len(applied), len(shipped))
	}
	for i, version := range applied {
		if version != shipped[i].version {
			return fmt.Errorf("schema migrations incomplete: expected version %d at position %d, got %d", shipped[i].version, i+1, version)
		}
	}
	return nil
}
