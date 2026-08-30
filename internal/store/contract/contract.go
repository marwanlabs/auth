// Package contract contains persistence behavior tests shared by store
// implementations.
//
// The suite is factory-based: callers supply a Factory that returns a fresh
// Repository for each subtest, so the same tests run unchanged against the
// JSON-backed reference store today and a database-backed store later (for
// example by returning the repository over a test database). Durability is
// covered separately by RunDurability, whose open function returns a fresh
// repository over the same persistent storage.
package contract

import (
	"errors"
	"testing"
	"time"

	"authserver/internal/store"
)

type CoreRepository interface {
	CreateUser(*store.User) error
	GetUserByID(string) (*store.User, error)
	GetUserByEmail(string) (*store.User, error)
	UpdateUser(*store.User) error
	DeleteUser(string) error
	CountUsers() int
	CountAdmins() int
	ListUsers() []*store.User
	CreateSession(*store.Session) error
	GetSession(string) (*store.Session, error)
	DeleteSession(string) error
	ListSessionsForUser(string) ([]*store.Session, error)
	DeleteExpiredSessions() error
	CreateResetToken(*store.ResetToken) error
	GetResetToken(string) (*store.ResetToken, error)
	DeleteResetToken(string) error
	GetIdentity(string, string) (*store.SocialIdentity, error)
	CreateIdentity(*store.SocialIdentity) error
	ListProviderSettings() map[string]bool
	ProviderSetting(string) (bool, bool)
	SetProviderEnabled(string, bool) error
}

type Repository interface {
	CoreRepository
	CreateOAuthTransaction(*store.OAuthTransaction) error
	ConsumeOAuthTransaction(string, string) (*store.OAuthTransaction, error)
}

type Factory func(*testing.T) Repository

func Run(t *testing.T, newRepository Factory) {
	t.Helper()
	RunCore(t, func(t *testing.T) CoreRepository { return newRepository(t) })
	t.Run("oauth transactions", func(t *testing.T) { testOAuthTransactions(t, newRepository(t)) })
	t.Run("oauth expiration cleanup", func(t *testing.T) { testOAuthExpirationCleanup(t, newRepository(t)) })
}

func RunCore(t *testing.T, newRepository func(*testing.T) CoreRepository) {
	t.Helper()
	t.Run("users", func(t *testing.T) { testUsers(t, newRepository(t)) })
	t.Run("user update and ordering", func(t *testing.T) { testUserUpdateAndOrdering(t, newRepository(t)) })
	t.Run("administrator counts", func(t *testing.T) { testAdministratorCounts(t, newRepository(t)) })
	t.Run("sessions", func(t *testing.T) { testSessions(t, newRepository(t)) })
	t.Run("reset tokens", func(t *testing.T) { testResetTokens(t, newRepository(t)) })
	t.Run("identities", func(t *testing.T) { testIdentities(t, newRepository(t)) })
	t.Run("providers", func(t *testing.T) { testProviders(t, newRepository(t)) })
	t.Run("deletion cascades", func(t *testing.T) { testDeletionCascades(t, newRepository(t)) })
	t.Run("expiration cleanup", func(t *testing.T) { testExpirationCleanup(t, newRepository(t)) })
}

func RunCoreDurability(t *testing.T, open func() CoreRepository) {
	t.Helper()
	r := open()
	u := user("durable", "durable@example.com", store.RoleUser)
	if err := r.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateSession(&store.Session{ID: "durable-session", UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateResetToken(&store.ResetToken{TokenHash: "durable-reset", UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateIdentity(&store.SocialIdentity{ID: "durable-identity", Provider: "github", Subject: "durable", UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	if err := r.SetProviderEnabled("github", true); err != nil {
		t.Fatal(err)
	}
	reopened := open()
	if got, err := reopened.GetUserByEmail(u.Email); err != nil || got.ID != u.ID {
		t.Fatalf("reopened user: %v, %v", got, err)
	}
	if _, err := reopened.GetSession("durable-session"); err != nil {
		t.Fatalf("reopened session: %v", err)
	}
	if _, err := reopened.GetResetToken("durable-reset"); err != nil {
		t.Fatalf("reopened reset token: %v", err)
	}
	if _, err := reopened.GetIdentity("github", "durable"); err != nil {
		t.Fatalf("reopened identity: %v", err)
	}
	if enabled, explicit := reopened.ProviderSetting("github"); !enabled || !explicit {
		t.Fatalf("reopened provider setting: %v, %v", enabled, explicit)
	}
}

// RunDurability checks that state survives closing and reopening the backing
// storage. The open function must return a fresh repository over that storage.
func RunDurability(t *testing.T, open func() Repository) {
	t.Helper()
	r := open()
	u := user("durable", "durable@example.com", store.RoleUser)
	if err := r.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateSession(&store.Session{ID: "durable-session", UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateResetToken(&store.ResetToken{TokenHash: "durable-reset", UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateIdentity(&store.SocialIdentity{ID: "durable-identity", Provider: "github", Subject: "durable", UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	if err := r.SetProviderEnabled("github", true); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateOAuthTransaction(&store.OAuthTransaction{ID: "durable-oauth", Provider: "github", PKCEVerifier: "durable-private", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	reopened := open()
	if got, err := reopened.GetUserByEmail(u.Email); err != nil || got.ID != u.ID {
		t.Fatalf("reopened user: %v, %v", got, err)
	}
	if _, err := reopened.GetSession("durable-session"); err != nil {
		t.Fatalf("reopened session: %v", err)
	}
	if _, err := reopened.GetResetToken("durable-reset"); err != nil {
		t.Fatalf("reopened reset token: %v", err)
	}
	if _, err := reopened.GetIdentity("github", "durable"); err != nil {
		t.Fatalf("reopened identity: %v", err)
	}
	if enabled, explicit := reopened.ProviderSetting("github"); !enabled || !explicit {
		t.Fatalf("reopened provider setting: %v, %v", enabled, explicit)
	}
	if tx, err := reopened.ConsumeOAuthTransaction("durable-oauth", "github"); err != nil || tx.PKCEVerifier != "durable-private" {
		t.Fatalf("reopened oauth transaction: %#v, %v", tx, err)
	}
}

func testUsers(t *testing.T, r CoreRepository) {
	first := user("first", "first@example.com", store.RoleUser)
	if err := r.CreateUser(first); err != nil {
		t.Fatal(err)
	}
	if got, err := r.GetUserByID(first.ID); err != nil || got.Email != first.Email {
		t.Fatalf("get by id: got %v, %v", got, err)
	}
	if got, err := r.GetUserByEmail(first.Email); err != nil || got.ID != first.ID {
		t.Fatalf("get by email: got %v, %v", got, err)
	}
	if err := r.CreateUser(user("duplicate", first.Email, store.RoleUser)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate email error = %v", err)
	}
	if _, err := r.GetUserByID("missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing user error = %v", err)
	}
	if err := r.UpdateUser(user("missing", "missing@example.com", store.RoleUser)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing update error = %v", err)
	}
}

func testUserUpdateAndOrdering(t *testing.T, r CoreRepository) {
	for _, u := range []*store.User{user("z", "z@example.com", store.RoleUser), user("a", "a@example.com", store.RoleUser)} {
		if err := r.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}
	users := r.ListUsers()
	if len(users) != 2 || users[0].Email != "a@example.com" || users[1].Email != "z@example.com" {
		t.Fatalf("users not ordered by email: %#v", users)
	}
	updated := users[0]
	updated.Disabled = true
	if err := r.UpdateUser(updated); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetUserByID(updated.ID)
	if err != nil || !got.Disabled {
		t.Fatalf("updated user: got %v, %v", got, err)
	}
}

func testAdministratorCounts(t *testing.T, r CoreRepository) {
	admin := user("admin", "admin@example.com", store.RoleAdmin)
	disabled := user("disabled", "disabled@example.com", store.RoleAdmin)
	disabled.Disabled = true
	for _, u := range []*store.User{admin, disabled, user("user", "user@example.com", store.RoleUser)} {
		if err := r.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.CountUsers(); got != 3 {
		t.Fatalf("user count = %d", got)
	}
	if got := r.CountAdmins(); got != 1 {
		t.Fatalf("active admin count = %d", got)
	}
}

func testSessions(t *testing.T, r CoreRepository) {
	session := &store.Session{ID: "session", UserID: "user", TokenHash: "hash", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := r.CreateSession(session); err != nil {
		t.Fatal(err)
	}
	if got, err := r.GetSession(session.ID); err != nil || got.TokenHash != session.TokenHash {
		t.Fatalf("get session: %v, %v", got, err)
	}
	list, err := r.ListSessionsForUser("user")
	if err != nil || len(list) != 1 {
		t.Fatalf("session list: %#v, %v", list, err)
	}
	if err := r.DeleteSession(session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetSession(session.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted session error = %v", err)
	}
}

func testResetTokens(t *testing.T, r CoreRepository) {
	token := &store.ResetToken{TokenHash: "reset", UserID: "user", ExpiresAt: time.Now().Add(time.Hour)}
	if err := r.CreateResetToken(token); err != nil {
		t.Fatal(err)
	}
	if got, err := r.GetResetToken(token.TokenHash); err != nil || got.UserID != token.UserID {
		t.Fatalf("get reset token: %v, %v", got, err)
	}
	if err := r.DeleteResetToken(token.TokenHash); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetResetToken(token.TokenHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted reset token error = %v", err)
	}
}

func testIdentities(t *testing.T, r CoreRepository) {
	identity := &store.SocialIdentity{ID: "identity", Provider: "github", Subject: "subject", UserID: "user", CreatedAt: time.Now()}
	if err := r.CreateIdentity(identity); err != nil {
		t.Fatal(err)
	}
	if got, err := r.GetIdentity(identity.Provider, identity.Subject); err != nil || got.UserID != identity.UserID {
		t.Fatalf("get identity: %v, %v", got, err)
	}
	if err := r.CreateIdentity(&store.SocialIdentity{ID: "other", Provider: identity.Provider, Subject: identity.Subject, UserID: "other-user"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate identity error = %v", err)
	}
	if _, err := r.GetIdentity("github", "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing identity error = %v", err)
	}
}

func testProviders(t *testing.T, r CoreRepository) {
	if settings := r.ListProviderSettings(); len(settings) != 0 {
		t.Fatalf("initial providers = %#v", settings)
	}
	if enabled, explicit := r.ProviderSetting("github"); enabled || explicit {
		t.Fatalf("initial setting = %v, %v", enabled, explicit)
	}
	if err := r.SetProviderEnabled("github", true); err != nil {
		t.Fatal(err)
	}
	if enabled, explicit := r.ProviderSetting("github"); !enabled || !explicit {
		t.Fatalf("enabled setting = %v, %v", enabled, explicit)
	}
	if settings := r.ListProviderSettings(); !settings["github"] {
		t.Fatalf("listed providers = %#v", settings)
	}
}

func testDeletionCascades(t *testing.T, r CoreRepository) {
	u := user("cascade", "cascade@example.com", store.RoleUser)
	if err := r.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateSession(&store.Session{ID: "cascade-session", UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateResetToken(&store.ResetToken{TokenHash: "cascade-reset", UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateIdentity(&store.SocialIdentity{ID: "cascade-identity", Provider: "github", Subject: "cascade", UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetSession("cascade-session"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cascaded session error = %v", err)
	}
	if _, err := r.GetResetToken("cascade-reset"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cascaded reset error = %v", err)
	}
	if _, err := r.GetIdentity("github", "cascade"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cascaded identity error = %v", err)
	}
	if err := r.DeleteUser(u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete error = %v", err)
	}
}

func testExpirationCleanup(t *testing.T, r CoreRepository) {
	if err := r.CreateSession(&store.Session{ID: "expired-session", UserID: "user", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateSession(&store.Session{ID: "active-session", UserID: "user", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateResetToken(&store.ResetToken{TokenHash: "expired-reset", UserID: "user", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateResetToken(&store.ResetToken{TokenHash: "active-reset", UserID: "user", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	sessions, err := r.ListSessionsForUser("user")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].ID != "active-session" {
		t.Fatalf("active session list = %v, want only the unexpired session", sessions)
	}
	if err := r.DeleteExpiredSessions(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetSession("expired-session"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session error = %v", err)
	}
	if _, err := r.GetResetToken("expired-reset"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired reset error = %v", err)
	}
	if _, err := r.GetSession("active-session"); err != nil {
		t.Fatalf("active session error = %v", err)
	}
	if _, err := r.GetResetToken("active-reset"); err != nil {
		t.Fatalf("active reset error = %v", err)
	}
}

func testOAuthTransactions(t *testing.T, r Repository) {
	tx := &store.OAuthTransaction{ID: "oauth", Provider: "github", PKCEVerifier: "private", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := r.CreateOAuthTransaction(tx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ConsumeOAuthTransaction(tx.ID, "google"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("provider mismatch error = %v", err)
	}
	got, err := r.ConsumeOAuthTransaction(tx.ID, tx.Provider)
	if err != nil || got.PKCEVerifier != tx.PKCEVerifier {
		t.Fatalf("consume = %#v, %v", got, err)
	}
	if _, err := r.ConsumeOAuthTransaction(tx.ID, tx.Provider); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("replay error = %v", err)
	}
}

func testOAuthExpirationCleanup(t *testing.T, r Repository) {
	if err := r.CreateOAuthTransaction(&store.OAuthTransaction{ID: "expired-oauth", Provider: "github", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteExpiredSessions(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ConsumeOAuthTransaction("expired-oauth", "github"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired oauth error = %v", err)
	}
}

func user(id, email string, role store.Role) *store.User {
	return &store.User{ID: id, Email: email, Role: role, CreatedAt: time.Now()}
}
