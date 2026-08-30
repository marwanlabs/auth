package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"authserver/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

// Store implements the core authentication repository over PostgreSQL.
// OAuth transactions and audit events deliberately remain separate capabilities.
type Store struct{ db *sql.DB }

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) CreateUser(u *store.User) error {
	_, err := s.db.ExecContext(context.Background(), `INSERT INTO users (id,email,google_id,password_hash,role,disabled,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, u.ID, u.Email, u.GoogleID, u.PasswordHash, u.Role, u.Disabled, u.CreatedAt)
	return translateError(err)
}

const userColumns = `id,email,google_id,password_hash,role,disabled,created_at`

func scanUser(row interface{ Scan(...any) error }) (*store.User, error) {
	u := new(store.User)
	if err := row.Scan(&u.ID, &u.Email, &u.GoogleID, &u.PasswordHash, &u.Role, &u.Disabled, &u.CreatedAt); err != nil {
		return nil, translateError(err)
	}
	return u, nil
}

func (s *Store) GetUserByID(id string) (*store.User, error) {
	return scanUser(s.db.QueryRowContext(context.Background(), `SELECT `+userColumns+` FROM users WHERE id=$1`, id))
}

func (s *Store) GetUserByEmail(email string) (*store.User, error) {
	return scanUser(s.db.QueryRowContext(context.Background(), `SELECT `+userColumns+` FROM users WHERE email=$1`, email))
}

func (s *Store) GetUserByGoogleID(googleID string) (*store.User, error) {
	return scanUser(s.db.QueryRowContext(context.Background(), `SELECT `+userColumns+` FROM users WHERE google_id=$1 AND google_id <> ''`, googleID))
}

func (s *Store) UpdateUser(u *store.User) error {
	result, err := s.db.ExecContext(context.Background(), `UPDATE users SET email=$2,google_id=$3,password_hash=$4,role=$5,disabled=$6,created_at=$7 WHERE id=$1`, u.ID, u.Email, u.GoogleID, u.PasswordHash, u.Role, u.Disabled, u.CreatedAt)
	if err != nil {
		return translateError(err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteUser(id string) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	result, err := tx.Exec(`DELETE FROM users WHERE id=$1`, id)
	if err != nil {
		_ = tx.Rollback()
		return translateError(err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return store.ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *Store) CountUsers() int {
	var n int
	_ = s.db.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n
}

func (s *Store) CountAdmins() int {
	var n int
	_ = s.db.QueryRow(`SELECT count(*) FROM users WHERE role=$1 AND NOT disabled`, store.RoleAdmin).Scan(&n)
	return n
}

func (s *Store) ListUsers() []*store.User {
	rows, err := s.db.Query(`SELECT ` + userColumns + ` FROM users ORDER BY email`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var users []*store.User
	for rows.Next() {
		if u, err := scanUser(rows); err == nil {
			users = append(users, u)
		}
	}
	return users
}

func (s *Store) CreateSession(v *store.Session) error {
	_, err := s.db.Exec(`INSERT INTO sessions (id,user_id,token_hash,created_at,expires_at,user_agent,ip) VALUES ($1,$2,$3,$4,$5,$6,$7)`, v.ID, v.UserID, v.TokenHash, v.CreatedAt, v.ExpiresAt, v.UserAgent, v.IP)
	return translateError(err)
}
func (s *Store) GetSession(id string) (*store.Session, error) {
	v := new(store.Session)
	err := s.db.QueryRow(`SELECT id,user_id,token_hash,created_at,expires_at,user_agent,ip FROM sessions WHERE id=$1`, id).Scan(&v.ID, &v.UserID, &v.TokenHash, &v.CreatedAt, &v.ExpiresAt, &v.UserAgent, &v.IP)
	if err != nil {
		return nil, translateError(err)
	}
	return v, nil
}
func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id=$1`, id)
	return err
}
func (s *Store) ListSessionsForUser(id string) ([]*store.Session, error) {
	rows, err := s.db.Query(`SELECT id,user_id,token_hash,created_at,expires_at,user_agent,ip FROM sessions WHERE user_id=$1 AND expires_at >= now()`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Session
	for rows.Next() {
		v := new(store.Session)
		if err := rows.Scan(&v.ID, &v.UserID, &v.TokenHash, &v.CreatedAt, &v.ExpiresAt, &v.UserAgent, &v.IP); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) DeleteExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < now()`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM reset_tokens WHERE expires_at < now()`)
	return err
}

func (s *Store) CreateResetToken(v *store.ResetToken) error {
	_, err := s.db.Exec(`INSERT INTO reset_tokens (token_hash,user_id,expires_at) VALUES ($1,$2,$3)`, v.TokenHash, v.UserID, v.ExpiresAt)
	return translateError(err)
}
func (s *Store) GetResetToken(hash string) (*store.ResetToken, error) {
	v := new(store.ResetToken)
	err := s.db.QueryRow(`SELECT token_hash,user_id,expires_at FROM reset_tokens WHERE token_hash=$1`, hash).Scan(&v.TokenHash, &v.UserID, &v.ExpiresAt)
	if err != nil {
		return nil, translateError(err)
	}
	return v, nil
}
func (s *Store) DeleteResetToken(hash string) error {
	_, err := s.db.Exec(`DELETE FROM reset_tokens WHERE token_hash=$1`, hash)
	return err
}

func (s *Store) GetIdentity(provider, subject string) (*store.SocialIdentity, error) {
	v := new(store.SocialIdentity)
	err := s.db.QueryRow(`SELECT id,provider,subject,user_id,created_at FROM social_identities WHERE provider=$1 AND subject=$2`, provider, subject).Scan(&v.ID, &v.Provider, &v.Subject, &v.UserID, &v.CreatedAt)
	if err != nil {
		return nil, translateError(err)
	}
	return v, nil
}
func (s *Store) CreateIdentity(v *store.SocialIdentity) error {
	_, err := s.db.Exec(`INSERT INTO social_identities (id,provider,subject,user_id,created_at) VALUES ($1,$2,$3,$4,$5)`, v.ID, v.Provider, v.Subject, v.UserID, v.CreatedAt)
	return translateError(err)
}
func (s *Store) ListProviderSettings() map[string]bool {
	rows, err := s.db.Query(`SELECT provider,enabled FROM provider_settings`)
	if err != nil {
		return map[string]bool{}
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var p string
		var e bool
		if rows.Scan(&p, &e) == nil {
			out[p] = e
		}
	}
	return out
}
func (s *Store) ProviderSetting(provider string) (bool, bool) {
	var enabled bool
	err := s.db.QueryRow(`SELECT enabled FROM provider_settings WHERE provider=$1`, provider).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false
	}
	return enabled, err == nil
}
func (s *Store) SetProviderEnabled(provider string, enabled bool) error {
	_, err := s.db.Exec(`INSERT INTO provider_settings (provider,enabled) VALUES ($1,$2) ON CONFLICT (provider) DO UPDATE SET enabled=EXCLUDED.enabled`, provider, enabled)
	return err
}

// CreateAuditEvent stores only the fields explicitly defined by the audit
// contract. event_order is generated by PostgreSQL for a durable tie-breaker.
func (s *Store) CreateAuditEvent(event *store.AuditEvent) error {
	if event.ID == "" {
		return fmt.Errorf("audit event ID is required")
	}
	_, err := s.db.Exec(`INSERT INTO audit_events (id,type,outcome,occurred_at,actor_id,actor_email,target,client_ip,user_agent) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, event.ID, event.Type, event.Outcome, event.Timestamp, event.ActorID, event.ActorEmail, event.Target, event.ClientIP, event.UserAgent)
	return translateError(err)
}

// ListAuditEvents returns events in chronological order. event_order makes
// ordering deterministic when events share the same timestamp.
func (s *Store) ListAuditEvents() []*store.AuditEvent {
	rows, err := s.db.Query(`SELECT id,type,outcome,occurred_at,actor_id,actor_email,target,client_ip,user_agent FROM audit_events ORDER BY occurred_at,event_order`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var events []*store.AuditEvent
	for rows.Next() {
		event := new(store.AuditEvent)
		if err := rows.Scan(&event.ID, &event.Type, &event.Outcome, &event.Timestamp, &event.ActorID, &event.ActorEmail, &event.Target, &event.ClientIP, &event.UserAgent); err != nil {
			return nil
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil
	}
	return events
}

func translateError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return store.ErrConflict
	}
	return fmt.Errorf("postgres store: %w", err)
}

var _ interface{ CreateUser(*store.User) error } = (*Store)(nil)
var _ store.AuditRepository = (*Store)(nil)
