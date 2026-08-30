package httpapi

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authserver/internal/auth"
	"authserver/internal/providers"
	"authserver/internal/store"
)

// adminTestAPI wires the full route surface (auth + provider routes) over a
// temporary store, so admin rate-limit and audit behavior is exercised at the
// route seam.
func adminTestAPI(t *testing.T) (*API, *store.Store, *http.ServeMux) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	api := New(&auth.Service{Store: s}, s, s, s, s, s, s)
	mux := http.NewServeMux()
	api.Register(mux)
	api.RegisterProviderRoutes(mux)
	return api, s, mux
}

// sessionCookie issues a session for userID directly and returns the cookie
// value a client would hold after signing in.
func sessionCookie(t *testing.T, s *store.Store, userID string) string {
	t.Helper()
	const token = "admin-test-token"
	sess := &store.Session{
		ID:        "admin-session-" + userID,
		UserID:    userID,
		TokenHash: auth.HashToken(token),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	return sess.ID + "." + token
}

// adminRequest sends a state-changing admin request with a session cookie,
// CSRF pair, and a decoy Authorization header that should never reach the
// audit trail. An empty cookie simulates an unauthenticated request.
func adminRequest(t *testing.T, mux *http.ServeMux, method, path, cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, rd)
	r.RemoteAddr = "198.51.100.1:1234"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer should-not-be-recorded")
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: cookie})
		r.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "csrf"})
		r.Header.Set(auth.CSRFHeaderName, "csrf")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func seedAdminAndTarget(t *testing.T, api *API) {
	t.Helper()
	for _, u := range []*store.User{
		{ID: "admin", Email: "admin@example.com", Role: store.RoleAdmin, CreatedAt: time.Now()},
		{ID: "target", Email: "target@example.com", Role: store.RoleUser, CreatedAt: time.Now()},
	} {
		if err := api.Users.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdminMutationsRateLimitWithoutChangingState(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		body  func(n int) string
		seed  func(t *testing.T, api *API)
		check func(t *testing.T, api *API)
	}{
		{
			name: "change user role",
			path: "/api/admin/users/role",
			body: func(int) string { return `{"user_id":"target","role":"admin"}` },
			seed: func(t *testing.T, api *API) { seedAdminAndTarget(t, api) },
			check: func(t *testing.T, api *API) {
				u, err := api.Users.GetUserByID("target")
				if err != nil {
					t.Fatal(err)
				}
				if u.Role != store.RoleAdmin {
					t.Fatalf("target role = %q, want admin", u.Role)
				}
			},
		},
		{
			name: "change user status",
			path: "/api/admin/users/status",
			body: func(int) string { return `{"user_id":"target","disabled":true}` },
			seed: func(t *testing.T, api *API) { seedAdminAndTarget(t, api) },
			check: func(t *testing.T, api *API) {
				u, err := api.Users.GetUserByID("target")
				if err != nil {
					t.Fatal(err)
				}
				if !u.Disabled {
					t.Fatal("target not disabled by allowed requests")
				}
			},
		},
		{
			name: "delete user",
			path: "/api/admin/users/delete",
			body: func(n int) string { return fmt.Sprintf(`{"user_id":"delete-%d"}`, n) },
			seed: func(t *testing.T, api *API) {
				seedAdminAndTarget(t, api)
				for i := 0; i < adminRateLimit; i++ {
					if err := api.Users.CreateUser(&store.User{ID: fmt.Sprintf("delete-%d", i), Email: fmt.Sprintf("delete-%d@example.com", i), Role: store.RoleUser}); err != nil {
						t.Fatal(err)
					}
				}
			},
			check: func(t *testing.T, api *API) {
				for i := 0; i < adminRateLimit; i++ {
					if _, err := api.Users.GetUserByID(fmt.Sprintf("delete-%d", i)); err == nil {
						t.Fatalf("delete-%d not deleted by allowed requests", i)
					}
				}
				if _, err := api.Users.GetUserByID("target"); err != nil {
					t.Fatalf("rate-limited request deleted an untouched user: %v", err)
				}
			},
		},
		{
			name: "set provider availability",
			path: "/api/admin/providers",
			body: func(int) string { return `{"provider":"github","enabled":true}` },
			seed: func(t *testing.T, api *API) {
				seedAdminAndTarget(t, api)
				api.Providers["github"] = providers.NewGitHub("client-id", "client-secret", "http://localhost/callback")
			},
			check: func(t *testing.T, api *API) {
				if enabled, explicit := api.ProviderDB.ProviderSetting("github"); !enabled || !explicit {
					t.Fatalf("github setting = (%v, %v), want (true, true)", enabled, explicit)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api, s, mux := adminTestAPI(t)
			tc.seed(t, api)
			cookie := sessionCookie(t, s, "admin")

			for i := 0; i < adminRateLimit; i++ {
				if got := adminRequest(t, mux, "POST", tc.path, cookie, tc.body(i)).Code; got != http.StatusOK {
					t.Fatalf("request %d status = %d, want %d", i+1, got, http.StatusOK)
				}
			}
			excess := adminRequest(t, mux, "POST", tc.path, cookie, tc.body(adminRateLimit))
			if excess.Code != http.StatusTooManyRequests {
				t.Fatalf("excess status = %d, want %d", excess.Code, http.StatusTooManyRequests)
			}
			tc.check(t, api)
		})
	}
}

func TestAdminMutationsProduceActionTargetOutcomeAuditEvents(t *testing.T) {
	api, s, mux := adminTestAPI(t)
	seedAdminAndTarget(t, api)
	if err := api.Users.CreateUser(&store.User{ID: "target-2", Email: "target2@example.com", Role: store.RoleUser, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	api.Providers["github"] = providers.NewGitHub("client-id", "client-secret", "http://localhost/callback")
	cookie := sessionCookie(t, s, "admin")

	steps := []struct {
		path string
		body string
	}{
		{"/api/admin/users/role", `{"user_id":"target","role":"admin"}`},
		{"/api/admin/users/status", `{"user_id":"target-2","disabled":true}`},
		{"/api/admin/users/delete", `{"user_id":"target-2"}`},
		{"/api/admin/providers", `{"provider":"github","enabled":true}`},
	}
	for _, step := range steps {
		if got := adminRequest(t, mux, "POST", step.path, cookie, step.body).Code; got != http.StatusOK {
			t.Fatalf("%s status = %d, want %d", step.path, got, http.StatusOK)
		}
	}

	want := []struct{ typ, target string }{
		{"admin.change_user_role", "target"},
		{"admin.change_user_status", "target-2"},
		{"admin.delete_user", "target-2"},
		{"admin.set_provider", "github"},
	}
	got := map[string]*store.AuditEvent{}
	for _, e := range s.ListAuditEvents() {
		got[e.Type] = e
	}
	if len(got) != len(want) {
		t.Fatalf("audit event count = %d, want %d", len(got), len(want))
	}
	for _, step := range want {
		e := got[step.typ]
		if e == nil {
			t.Fatalf("no audit event of type %q", step.typ)
		}
		if e.Outcome != "success" || e.Target != step.target {
			t.Fatalf("%s event = %+v, want outcome=success target=%s", step.typ, e, step.target)
		}
		if e.Timestamp.IsZero() {
			t.Fatalf("%s event missing timestamp", step.typ)
		}
		if e.ActorID != "admin" || e.ActorEmail != "admin@example.com" {
			t.Fatalf("%s event actor = %s/%s, want admin", step.typ, e.ActorID, e.ActorEmail)
		}
		if e.ClientIP != "198.51.100.1:1234" {
			t.Fatalf("%s event client ip = %q", step.typ, e.ClientIP)
		}
		if strings.Contains(string(mustJSON(e)), "should-not-be-recorded") {
			t.Fatalf("%s audit event leaked a request secret", step.typ)
		}
	}
}

func TestFailedAdminMutationIsAudited(t *testing.T) {
	api, s, mux := adminTestAPI(t)
	seedAdminAndTarget(t, api)
	cookie := sessionCookie(t, s, "admin")

	res := adminRequest(t, mux, "POST", "/api/admin/users/role", cookie, `{"user_id":"ghost","role":"admin"}`)
	if res.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusNotFound)
	}
	events := s.ListAuditEvents()
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	if e := events[0]; e.Type != "admin.change_user_role" || e.Outcome != "failure" || e.Target != "ghost" {
		t.Fatalf("audit event = %+v, want role-change failure on ghost", e)
	}
}

func TestUnauthorizedAdminMutationCannotActAndIsAuditedAsForbidden(t *testing.T) {
	api, s, mux := adminTestAPI(t)
	seedAdminAndTarget(t, api)

	anon := adminRequest(t, mux, "POST", "/api/admin/users/role", "", `{"user_id":"target","role":"admin"}`)
	if anon.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want %d", anon.Code, http.StatusUnauthorized)
	}

	nonAdmin := adminRequest(t, mux, "POST", "/api/admin/users/role", sessionCookie(t, s, "target"), `{"user_id":"target","role":"admin"}`)
	if nonAdmin.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, want %d", nonAdmin.Code, http.StatusForbidden)
	}

	if u, err := api.Users.GetUserByID("target"); err != nil || u.Role != store.RoleUser {
		t.Fatalf("unauthorized request changed role: role=%q err=%v", u.Role, err)
	}

	events := s.ListAuditEvents()
	if len(events) != 2 {
		t.Fatalf("audit event count = %d, want 2", len(events))
	}
	byActor := map[string]*store.AuditEvent{}
	for _, e := range events {
		byActor[e.ActorID] = e
	}
	anonEvent := byActor[""]
	if anonEvent == nil || anonEvent.Type != "admin.change_user_role" || anonEvent.Outcome != "forbidden" {
		t.Fatalf("anonymous audit event = %+v", anonEvent)
	}
	userEvent := byActor["target"]
	if userEvent == nil || userEvent.Type != "admin.change_user_role" || userEvent.Outcome != "forbidden" || userEvent.Target != "target" {
		t.Fatalf("non-admin audit event = %+v", userEvent)
	}
}
