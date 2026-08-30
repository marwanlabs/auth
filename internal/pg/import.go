package pg

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"authserver/internal/store"
)

var (
	ErrImportRejected  = errors.New("JSON import rejected records")
	ErrAlreadyImported = errors.New("JSON import has already been completed")
)

type Rejection struct{ Category, Key, Reason string }
type CategoryReport struct {
	Migrated, Rejected int
	Rejections         []Rejection
}
type ImportReport struct {
	Users, Credentials, SocialIdentities, Sessions, ResetTokens, Providers, AuditEvents, OAuthTransactions CategoryReport
	Committed, RolledBack, AlreadyImported                                                                 bool
}

func (r *ImportReport) category(name, key, reason string) *CategoryReport {
	var c *CategoryReport
	switch name {
	case "users":
		c = &r.Users
	case "credentials":
		c = &r.Credentials
	case "social_identities":
		c = &r.SocialIdentities
	case "sessions":
		c = &r.Sessions
	case "reset_tokens":
		c = &r.ResetTokens
	case "providers":
		c = &r.Providers
	case "audit_events":
		c = &r.AuditEvents
	case "oauth_transactions":
		c = &r.OAuthTransactions
	}
	c.Rejected++
	c.Rejections = append(c.Rejections, Rejection{Category: name, Key: key, Reason: reason})
	return c
}

func ImportJSON(ctx context.Context, db *sql.DB, path string) (ImportReport, error) {
	var report ImportReport
	source, err := store.Open(path)
	if err != nil {
		return report, err
	}
	snapshot := source.Snapshot()
	raw, err := os.ReadFile(path)
	if err != nil {
		return report, fmt.Errorf("read JSON store after load: %w", err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	validateSnapshot(snapshot, &report)
	if hasRejections(report) {
		report.RolledBack = true
		return report, ErrImportRejected
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return report, fmt.Errorf("begin JSON import: %w", err)
	}
	defer tx.Rollback()
	var marker bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM json_imports)`).Scan(&marker)
	if err != nil {
		report.RolledBack = true
		return report, fmt.Errorf("check JSON import ledger: %w", err)
	}
	if marker {
		report.AlreadyImported = true
		report.RolledBack = true
		return report, ErrAlreadyImported
	}
	if err := insertSnapshot(ctx, tx, snapshot); err != nil {
		report.RolledBack = true
		return report, rollbackError(tx, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO json_imports (id,source_path,source_sha256) VALUES (true,$1,$2)`, path, digest); err != nil {
		report.RolledBack = true
		return report, rollbackError(tx, fmt.Errorf("record JSON import: %w", err))
	}
	if err := tx.Commit(); err != nil {
		report.RolledBack = true
		return report, fmt.Errorf("commit JSON import: %w", err)
	}
	report.Committed = true
	return report, nil
}

func rollbackError(tx *sql.Tx, err error) error {
	_ = tx.Rollback()
	return fmt.Errorf("JSON import rolled back: %w", err)
}

func validateSnapshot(s store.Snapshot, r *ImportReport) {
	users := make(map[string]bool, len(s.Users))
	emails := make(map[string]bool, len(s.Users))
	identities := make(map[string]bool, len(s.Identities))
	for _, u := range s.Users {
		if u == nil {
			r.category("users", "", "null record")
			continue
		}
		if u.ID == "" {
			r.category("users", u.ID, "missing ID")
			continue
		}
		if users[u.ID] {
			r.category("users", u.ID, "duplicate ID")
			continue
		}
		users[u.ID] = true
		if strings.TrimSpace(u.Email) == "" {
			r.category("users", u.ID, "missing email")
			continue
		}
		if emails[u.Email] {
			r.category("users", u.ID, "duplicate email")
			continue
		}
		emails[u.Email] = true
		r.Users.Migrated++
		if u.PasswordHash != "" {
			r.Credentials.Migrated++
		}
	}
	for _, v := range s.Identities {
		if v == nil || v.ID == "" || v.Provider == "" || v.Subject == "" || !users[v.UserID] {
			r.category("social_identities", keyIdentity(v), "invalid identity or user reference")
			continue
		}
		identityKey := v.Provider + "\x00" + v.Subject
		if identities[identityKey] {
			r.category("social_identities", v.ID, "duplicate provider and subject")
			continue
		}
		identities[identityKey] = true
		r.SocialIdentities.Migrated++
	}
	for _, v := range s.Sessions {
		if v == nil || v.ID == "" || v.TokenHash == "" || !users[v.UserID] {
			r.category("sessions", keySession(v), "invalid session or user reference")
			continue
		}
		r.Sessions.Migrated++
	}
	for _, v := range s.ResetTokens {
		if v == nil || v.TokenHash == "" || !users[v.UserID] {
			r.category("reset_tokens", keyReset(v), "invalid reset token or user reference")
			continue
		}
		r.ResetTokens.Migrated++
	}
	for p := range s.Providers {
		if strings.TrimSpace(p) == "" {
			r.category("providers", p, "missing provider")
			continue
		}
		r.Providers.Migrated++
	}
	for _, v := range s.AuditEvents {
		if v == nil || v.ID == "" || v.Type == "" || v.Outcome == "" {
			r.category("audit_events", keyAudit(v), "missing required audit field")
			continue
		}
		r.AuditEvents.Migrated++
	}
	for _, v := range s.OAuth {
		if v == nil || v.ID == "" || v.Provider == "" || v.CreatedAt.IsZero() || v.ExpiresAt.IsZero() {
			r.category("oauth_transactions", keyOAuth(v), "missing required field")
			continue
		}
		if v.PKCEVerifier == "" {
			r.category("oauth_transactions", v.ID, "missing PKCE verifier")
			continue
		}
		r.OAuthTransactions.Migrated++
	}
}

func hasRejections(r ImportReport) bool {
	return r.Users.Rejected+r.Credentials.Rejected+r.SocialIdentities.Rejected+r.Sessions.Rejected+r.ResetTokens.Rejected+r.Providers.Rejected+r.AuditEvents.Rejected+r.OAuthTransactions.Rejected > 0
}
func keyIdentity(v *store.SocialIdentity) string {
	if v == nil {
		return ""
	}
	return v.ID
}
func keySession(v *store.Session) string {
	if v == nil {
		return ""
	}
	return v.ID
}
func keyReset(v *store.ResetToken) string {
	if v == nil {
		return ""
	}
	return v.TokenHash
}
func keyAudit(v *store.AuditEvent) string {
	if v == nil {
		return ""
	}
	return v.ID
}
func keyOAuth(v *store.OAuthTransaction) string {
	if v == nil {
		return ""
	}
	return v.ID
}

func insertSnapshot(ctx context.Context, tx *sql.Tx, s store.Snapshot) error {
	for _, v := range s.Users {
		if _, err := tx.ExecContext(ctx, `INSERT INTO users (id,email,google_id,password_hash,role,disabled,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, v.ID, v.Email, v.GoogleID, v.PasswordHash, v.Role, v.Disabled, v.CreatedAt); err != nil {
			return fmt.Errorf("user %s: %w", v.ID, err)
		}
	}
	for _, v := range s.Identities {
		if _, err := tx.ExecContext(ctx, `INSERT INTO social_identities (id,provider,subject,user_id,created_at) VALUES ($1,$2,$3,$4,$5)`, v.ID, v.Provider, v.Subject, v.UserID, v.CreatedAt); err != nil {
			return fmt.Errorf("identity %s: %w", v.ID, err)
		}
	}
	for _, v := range s.Sessions {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sessions (id,user_id,token_hash,created_at,expires_at,user_agent,ip) VALUES ($1,$2,$3,$4,$5,$6,$7)`, v.ID, v.UserID, v.TokenHash, v.CreatedAt, v.ExpiresAt, v.UserAgent, v.IP); err != nil {
			return fmt.Errorf("session %s: %w", v.ID, err)
		}
	}
	for _, v := range s.ResetTokens {
		if _, err := tx.ExecContext(ctx, `INSERT INTO reset_tokens (token_hash,user_id,expires_at) VALUES ($1,$2,$3)`, v.TokenHash, v.UserID, v.ExpiresAt); err != nil {
			return fmt.Errorf("reset token %s: %w", v.TokenHash, err)
		}
	}
	for p, enabled := range s.Providers {
		if _, err := tx.ExecContext(ctx, `INSERT INTO provider_settings (provider,enabled) VALUES ($1,$2)`, p, enabled); err != nil {
			return fmt.Errorf("provider %s: %w", p, err)
		}
	}
	for _, v := range s.AuditEvents {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events (id,type,outcome,occurred_at,actor_id,actor_email,target,client_ip,user_agent) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, v.ID, v.Type, v.Outcome, v.Timestamp, v.ActorID, v.ActorEmail, v.Target, v.ClientIP, v.UserAgent); err != nil {
			return fmt.Errorf("audit event %s: %w", v.ID, err)
		}
	}
	for _, v := range s.OAuth {
		if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_transactions (id,provider,pkce_verifier,created_at,expires_at) VALUES ($1,$2,$3,$4,$5)`, v.ID, v.Provider, v.PKCEVerifier, v.CreatedAt, v.ExpiresAt); err != nil {
			return fmt.Errorf("OAuth transaction %s: %w", v.ID, err)
		}
	}
	return nil
}
