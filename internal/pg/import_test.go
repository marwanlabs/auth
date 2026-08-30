package pg

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"authserver/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestValidateSnapshotReportsEveryCategoryAndUnsafeOAuth(t *testing.T) {
	now := time.Now()
	snapshot := store.Snapshot{
		Users:       []*store.User{{ID: "u", Email: "u@example.com", CreatedAt: now, PasswordHash: "hash"}, {ID: "", Email: "bad"}},
		Identities:  []*store.SocialIdentity{{ID: "i", Provider: "github", Subject: "s", UserID: "u"}, {ID: "bad", UserID: "missing"}},
		Sessions:    []*store.Session{{ID: "s", UserID: "u", TokenHash: "hash"}, {ID: "bad", UserID: "missing"}},
		ResetTokens: []*store.ResetToken{{TokenHash: "r", UserID: "u"}, {TokenHash: "bad", UserID: "missing"}},
		Providers:   map[string]bool{"github": true, "": false},
		AuditEvents: []*store.AuditEvent{{ID: "a", Type: "login", Outcome: "success"}, {ID: "bad"}},
		OAuth:       []*store.OAuthTransaction{{ID: "o", Provider: "github", PKCEVerifier: "private", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, {ID: "safe", Provider: "github", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}},
	}
	var report ImportReport
	validateSnapshot(snapshot, &report)
	if !hasRejections(report) {
		t.Fatal("expected rejected records")
	}
	for name, rejected := range map[string]int{
		"users": report.Users.Rejected, "social identities": report.SocialIdentities.Rejected,
		"sessions": report.Sessions.Rejected, "reset tokens": report.ResetTokens.Rejected,
		"providers": report.Providers.Rejected, "audit events": report.AuditEvents.Rejected,
		"oauth transactions": report.OAuthTransactions.Rejected,
	} {
		if rejected == 0 {
			t.Errorf("%s: no rejected records", name)
		}
	}
	if report.Credentials.Migrated != 1 {
		t.Errorf("credentials migrated = %d, want 1", report.Credentials.Migrated)
	}
	if report.OAuthTransactions.Migrated != 1 {
		t.Errorf("safe OAuth migrated = %d, want 1", report.OAuthTransactions.Migrated)
	}
	if report.OAuthTransactions.Rejections[0].Reason == "" {
		t.Error("OAuth rejection has no reason")
	}
}

func TestPostgresJSONImportRollbackRepeatAndAllCategories(t *testing.T) {
	baseURL := os.Getenv("TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL JSON import")
	}
	ctx := context.Background()
	cfg, err := ParseConfig(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := Connect(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "auth_import_test_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	quoted := `"` + strings.ReplaceAll(schema, `"`, `""`) + `"`
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+quoted+" CASCADE")
	connCfg, err := pgx.ParseConfig(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	if connCfg.Config.RuntimeParams == nil {
		connCfg.Config.RuntimeParams = map[string]string{}
	}
	connCfg.Config.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*connCfg)
	defer db.Close()
	if _, err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/store.json"
	json := `{"users":{"u1":{"id":"u1","email":"u1@example.com","password_hash":"pbkdf2$hash","role":"user","created_at":"2026-01-01T00:00:00Z"},"u2":{"id":"u2","email":"u2@example.com","role":"admin","created_at":"2026-01-01T00:00:00Z"}},"sessions":{"s1":{"id":"s1","user_id":"u1","token_hash":"sha256-session","created_at":"2026-01-01T00:00:00Z","expires_at":"2030-01-01T00:00:00Z","user_agent":"test","ip":"127.0.0.1"}},"reset_tokens":{"sha256-reset":{"token_hash":"sha256-reset","user_id":"u1","expires_at":"2030-01-01T00:00:00Z"}},"oauth_transactions":{"o1":{"id":"o1","provider":"github","created_at":"2026-01-01T00:00:00Z","expires_at":"2030-01-01T00:00:00Z"}},"social_identities":{"i1":{"id":"i1","provider":"github","subject":"subject-1","user_id":"u1","created_at":"2026-01-01T00:00:00Z"}},"enabled_providers":{"github":true},"audit_events":{"a1":{"id":"a1","type":"import","outcome":"success","timestamp":"2026-01-01T00:00:00Z"}}}`
	if err := os.WriteFile(path, []byte(json), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id,email,role,created_at) VALUES ('u1','existing@example.com','user','2025-01-01')`); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportJSON(ctx, db, path); err == nil {
		t.Fatal("expected conflicting import to fail")
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("audit rows after rollback = %d, want 0", count)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id='u1'`); err != nil {
		t.Fatal(err)
	}
	report, err := ImportJSON(ctx, db, path)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Committed || report.Users.Migrated != 2 || report.Credentials.Migrated != 1 || report.SocialIdentities.Migrated != 1 || report.Sessions.Migrated != 1 || report.ResetTokens.Migrated != 1 || report.Providers.Migrated != 1 || report.AuditEvents.Migrated != 1 || report.OAuthTransactions.Migrated != 1 {
		t.Fatalf("unexpected import report: %+v", report)
	}
	repeat, err := ImportJSON(ctx, db, path)
	if !errors.Is(err, ErrAlreadyImported) || !repeat.AlreadyImported || !repeat.RolledBack {
		t.Fatalf("unexpected repeat result: %+v, %v", repeat, err)
	}
}
