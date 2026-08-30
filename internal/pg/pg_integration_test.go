package pg

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"authserver/internal/store/contract"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// TestPostgresRepeatableInitialization is the PostgreSQL integration
// environment: it verifies schema initialization is repeatable against a real
// server. It skips unless TEST_DATABASE_URL is set, and isolates every run in
// a freshly created schema so it can be safely run many times against a
// shared database. Example:
//
//	TEST_DATABASE_URL='postgres://postgres:secret@localhost:5432/postgres?sslmode=disable' \
//	    go test ./internal/pg -run TestPostgresRepeatableInitialization -v
func TestPostgresRepeatableInitialization(t *testing.T) {
	baseURL := os.Getenv("TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	ctx := context.Background()

	cfg, err := ParseConfig(baseURL)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	admin, err := Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("connecting to test database: %v", err)
	}
	defer admin.Close()

	schema := "auth_mig_test_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	quoted := `"` + strings.ReplaceAll(schema, `"`, `""`) + `"`
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatalf("creating test schema: %v", err)
	}
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+quoted+" CASCADE")

	// newPool opens an isolated connection pool whose default search_path is
	// the fresh schema, so migrations and queries stay inside it.
	newPool := func(t *testing.T) *sql.DB {
		t.Helper()
		connCfg, err := pgx.ParseConfig(baseURL)
		if err != nil {
			t.Fatalf("parse test url: %v", err)
		}
		if connCfg.Config.RuntimeParams == nil {
			connCfg.Config.RuntimeParams = make(map[string]string)
		}
		connCfg.Config.RuntimeParams["search_path"] = schema
		db := stdlib.OpenDB(*connCfg)
		t.Cleanup(func() { db.Close() })
		return db
	}

	shipped, err := migrations()
	if err != nil {
		t.Fatalf("migrations(): %v", err)
	}
	wantVersion := shipped[len(shipped)-1].version

	db := newPool(t)

	// A fresh database initializes to the current schema version...
	version, err := Migrate(ctx, db)
	if err != nil {
		t.Fatalf("initial migrate: %v", err)
	}
	if version != wantVersion {
		t.Errorf("initial migrate returned version %d, want %d", version, wantVersion)
	}

	// ...and re-applying immediately is a repeatable no-op.
	version, err = Migrate(ctx, db)
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if version != wantVersion {
		t.Errorf("second migrate returned version %d, want %d", version, wantVersion)
	}

	// The version ledger records exactly the migrations this binary ships, in
	// order, with their embedded names.
	ledger := appliedLedger(ctx, t, db)
	for _, m := range shipped {
		if _, ok := ledger[m.version]; !ok {
			t.Errorf("migration %d (%s) missing from schema_migrations", m.version, m.name)
		}
	}
	if len(ledger) != len(shipped) {
		t.Errorf("schema_migrations has %d rows, want %d", len(ledger), len(shipped))
	}
	assertTable(ctx, t, db, schema, "schema_migrations")
	assertTable(ctx, t, db, schema, "app_metadata")

	// A second, independent pool over the same schema converges to the same
	// version: initialization is repeatable across runtimes.
	second := newPool(t)
	version, err = Migrate(ctx, second)
	if err != nil {
		t.Fatalf("migrate from second pool: %v", err)
	}
	if version != wantVersion {
		t.Errorf("second pool migrated to version %d, want %d", version, wantVersion)
	}
}

func TestPostgresCoreStoreContract(t *testing.T) {
	baseURL := os.Getenv("TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL core store contract")
	}
	ctx := context.Background()
	adminCfg, err := ParseConfig(baseURL)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	admin, err := Connect(ctx, adminCfg)
	if err != nil {
		t.Fatalf("connecting to test database: %v", err)
	}
	defer admin.Close()
	schema := "auth_store_test_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	quoted := `"` + strings.ReplaceAll(schema, `"`, `""`) + `"`
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatalf("creating test schema: %v", err)
	}
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+quoted+" CASCADE")

	newDB := func() *sql.DB {
		cfg, err := pgx.ParseConfig(baseURL)
		if err != nil {
			t.Fatalf("parse test URL: %v", err)
		}
		if cfg.Config.RuntimeParams == nil {
			cfg.Config.RuntimeParams = map[string]string{}
		}
		cfg.Config.RuntimeParams["search_path"] = schema
		return stdlib.OpenDB(*cfg)
	}
	db := newDB()
	defer db.Close()
	if _, err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	contract.RunCore(t, func(t *testing.T) contract.CoreRepository {
		if _, err := db.ExecContext(ctx, `DELETE FROM users`); err != nil {
			t.Fatalf("reset users: %v", err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM provider_settings`); err != nil {
			t.Fatalf("reset provider settings: %v", err)
		}
		return NewStore(db)
	})
	if _, err := db.ExecContext(ctx, `DELETE FROM users`); err != nil {
		t.Fatalf("reset users for durability: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM provider_settings`); err != nil {
		t.Fatalf("reset provider settings for durability: %v", err)
	}
	contract.RunCoreDurability(t, func() contract.CoreRepository { return NewStore(db) })
}

func appliedLedger(ctx context.Context, t *testing.T, db *sql.DB) map[int64]bool {
	t.Helper()
	rows, err := db.QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		t.Fatalf("reading schema_migrations: %v", err)
	}
	defer rows.Close()
	applied := make(map[int64]bool)
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			t.Fatalf("scanning schema_migrations: %v", err)
		}
		applied[version] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating schema_migrations: %v", err)
	}
	return applied
}

func assertTable(ctx context.Context, t *testing.T, db *sql.DB, schema, table string) {
	t.Helper()
	var exists bool
	err := db.QueryRowContext(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM information_schema.tables
		   WHERE table_schema = $1 AND table_name = $2
		 )`, schema, table).Scan(&exists)
	if err != nil {
		t.Fatalf("checking for table %s.%s: %v", schema, table, err)
	}
	if !exists {
		t.Errorf("table %s.%s not present after migration", schema, table)
	}
}
