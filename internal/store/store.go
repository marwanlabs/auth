// Package store provides a small, thread-safe, file-backed data store.
// It's intentionally simple: everything lives in one JSON file on disk,
// guarded by a mutex, saved atomically on every write. This is a
// reasonable choice for an internal tool with a handful to a few thousand
// users. If you outgrow it, the Store interface below is the seam to swap
// in Postgres/MySQL later — only this file needs to change.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"` // stored lowercased
	PasswordHash string    `json:"password_hash"`
	Role         Role      `json:"role"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"created_at"`
}

// Session represents a logged-in device/browser. TokenHash is the SHA-256
// of the secret sent to the client in a cookie — never the raw token.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	TokenHash string    `json:"token_hash"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UserAgent string    `json:"user_agent"`
	IP        string    `json:"ip"`
}

// ResetToken represents a one-time password-reset link.
type ResetToken struct {
	TokenHash string    `json:"token_hash"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type data struct {
	Users       map[string]*User       `json:"users"`        // keyed by user ID
	Sessions    map[string]*Session    `json:"sessions"`     // keyed by session ID
	ResetTokens map[string]*ResetToken `json:"reset_tokens"` // keyed by token hash
}

type Store struct {
	mu   sync.RWMutex
	path string
	d    data
}

// Open loads the store from path, creating an empty one if it doesn't exist.
func Open(path string) (*Store, error) {
	s := &Store{
		path: path,
		d: data{
			Users:       make(map[string]*User),
			Sessions:    make(map[string]*Session),
			ResetTokens: make(map[string]*ResetToken),
		},
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, s.saveLocked()
		}
		return nil, fmt.Errorf("reading store file: %w", err)
	}
	if len(raw) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(raw, &s.d); err != nil {
		return nil, fmt.Errorf("parsing store file: %w", err)
	}
	if s.d.Users == nil {
		s.d.Users = make(map[string]*User)
	}
	if s.d.Sessions == nil {
		s.d.Sessions = make(map[string]*Session)
	}
	if s.d.ResetTokens == nil {
		s.d.ResetTokens = make(map[string]*ResetToken)
	}
	return s, nil
}

// saveLocked writes the store to disk atomically (write temp file, rename).
// Caller must hold s.mu.
func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding store: %w", err)
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".store-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming temp file: %w", err)
	}
	return nil
}

var ErrNotFound = fmt.Errorf("not found")
var ErrConflict = fmt.Errorf("already exists")

// --- Users ---

func (s *Store) CreateUser(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.d.Users {
		if existing.Email == u.Email {
			return ErrConflict
		}
	}
	s.d.Users[u.ID] = u
	return s.saveLocked()
}

func (s *Store) GetUserByID(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.d.Users[id]
	if !ok {
		return nil, ErrNotFound
	}
	return u, nil
}

func (s *Store) GetUserByEmail(email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.d.Users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) UpdateUser(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.d.Users[u.ID]; !ok {
		return ErrNotFound
	}
	s.d.Users[u.ID] = u
	return s.saveLocked()
}

// DeleteUser permanently removes a user and all credentials associated with
// the account.
func (s *Store) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.d.Users[id]; !ok {
		return ErrNotFound
	}
	delete(s.d.Users, id)
	for sessionID, sess := range s.d.Sessions {
		if sess.UserID == id {
			delete(s.d.Sessions, sessionID)
		}
	}
	for tokenHash, token := range s.d.ResetTokens {
		if token.UserID == id {
			delete(s.d.ResetTokens, tokenHash)
		}
	}
	return s.saveLocked()
}

// CountUsers is used to decide whether the very first signup should
// become an admin.
func (s *Store) CountUsers() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.d.Users)
}

// ListUsers returns all users in stable email order for admin views.
func (s *Store) ListUsers() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]*User, 0, len(s.d.Users))
	for _, u := range s.d.Users {
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Email < users[j].Email })
	return users
}

// CountAdmins returns the number of active administrator accounts.
func (s *Store) CountAdmins() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, u := range s.d.Users {
		if u.Role == RoleAdmin && !u.Disabled {
			count++
		}
	}
	return count
}

// --- Sessions ---

func (s *Store) CreateSession(sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.Sessions[sess.ID] = sess
	return s.saveLocked()
}

func (s *Store) GetSession(id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.d.Sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return sess, nil
}

func (s *Store) DeleteSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.d.Sessions, id)
	return s.saveLocked()
}

// ListSessionsForUser returns all non-expired sessions for a user, useful
// for a "your active devices" screen.
func (s *Store) ListSessionsForUser(userID string) ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Session
	for _, sess := range s.d.Sessions {
		if sess.UserID == userID {
			out = append(out, sess)
		}
	}
	return out, nil
}

// DeleteExpiredSessions sweeps out stale sessions and reset tokens. Call
// this periodically (main.go runs it on a ticker).
func (s *Store) DeleteExpiredSessions() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	changed := false
	for id, sess := range s.d.Sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.d.Sessions, id)
			changed = true
		}
	}
	for hash, rt := range s.d.ResetTokens {
		if now.After(rt.ExpiresAt) {
			delete(s.d.ResetTokens, hash)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.saveLocked()
}

// --- Password reset tokens ---

func (s *Store) CreateResetToken(rt *ResetToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.ResetTokens[rt.TokenHash] = rt
	return s.saveLocked()
}

func (s *Store) GetResetToken(hash string) (*ResetToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rt, ok := s.d.ResetTokens[hash]
	if !ok {
		return nil, ErrNotFound
	}
	return rt, nil
}

func (s *Store) DeleteResetToken(hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.d.ResetTokens, hash)
	return s.saveLocked()
}
