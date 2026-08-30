package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"authserver/internal/auth"
	"authserver/internal/store"
)

func testAPI(t *testing.T) (*API, *http.ServeMux) {
	t.Helper()
	s, err := store.Open(t.TempDir() + "/store.json")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	api := New(&auth.Service{Store: s}, s, s, s, s, s, s)
	mux := http.NewServeMux()
	api.Register(mux)
	return api, mux
}

func request(t *testing.T, mux *http.ServeMux, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.RemoteAddr = "198.51.100.1:1234"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestSignupRateLimitStopsRequestsBeforeCreatingUser(t *testing.T) {
	api, mux := testAPI(t)

	for i := 0; i < 10; i++ {
		body := fmt.Sprintf(`{"email":"user-%d@example.com","password":"long enough password"}`, i)
		if got := request(t, mux, "/api/signup", body).Code; got != http.StatusCreated {
			t.Fatalf("request %d status = %d, want %d", i+1, got, http.StatusCreated)
		}
	}
	if got := request(t, mux, "/api/signup", `{}`).Code; got != http.StatusTooManyRequests {
		t.Fatalf("excess signup status = %d, want %d", got, http.StatusTooManyRequests)
	}
	if got := api.Users.CountUsers(); got != 10 {
		t.Fatalf("user count = %d, want 10", got)
	}
	sessions := 0
	for _, u := range api.Users.ListUsers() {
		userSessions, err := api.Sessions.ListSessionsForUser(u.ID)
		if err != nil {
			t.Fatalf("list sessions: %v", err)
		}
		sessions += len(userSessions)
	}
	if sessions != 10 {
		t.Fatalf("session count = %d, want 10", sessions)
	}
}

func TestLoginRateLimitStopsRequestsBeforeCreatingSession(t *testing.T) {
	api, mux := testAPI(t)

	for i := 0; i < 10; i++ {
		if got := request(t, mux, "/api/login", `{"email":"missing@example.com","password":"wrong"}`).Code; got != http.StatusUnauthorized {
			t.Fatalf("request %d status = %d, want %d", i+1, got, http.StatusUnauthorized)
		}
	}
	if got := request(t, mux, "/api/login", `{"email":"missing@example.com","password":"wrong"}`).Code; got != http.StatusTooManyRequests {
		t.Fatalf("excess login status = %d, want %d", got, http.StatusTooManyRequests)
	}
	if got := len(api.Users.ListUsers()); got != 0 {
		t.Fatalf("user count = %d, want 0", got)
	}
}

func TestLoginAndSignupHaveIndependentRateLimits(t *testing.T) {
	_, mux := testAPI(t)

	for i := 0; i < 10; i++ {
		if got := request(t, mux, "/api/signup", `{}`).Code; got != http.StatusBadRequest {
			t.Fatalf("signup request %d status = %d, want %d", i+1, got, http.StatusBadRequest)
		}
	}
	if got := request(t, mux, "/api/login", `{"email":"missing@example.com","password":"wrong"}`).Code; got != http.StatusUnauthorized {
		t.Fatalf("login status after signup limit = %d, want %d", got, http.StatusUnauthorized)
	}
}

func TestAuthenticationResponsesRemainEnumerationSafe(t *testing.T) {
	api, mux := testAPI(t)
	hash, err := auth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := api.Users.CreateUser(&store.User{ID: "user-1", Email: "known@example.com", PasswordHash: hash, Role: store.RoleUser}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	missing := request(t, mux, "/api/login", `{"email":"missing@example.com","password":"wrong"}`)
	wrongPassword := request(t, mux, "/api/login", `{"email":"known@example.com","password":"wrong"}`)
	if missing.Code != http.StatusUnauthorized || wrongPassword.Code != http.StatusUnauthorized {
		t.Fatalf("login statuses = %d and %d, want %d", missing.Code, wrongPassword.Code, http.StatusUnauthorized)
	}
	if missing.Body.String() != wrongPassword.Body.String() {
		t.Fatalf("login responses differ: %q vs %q", missing.Body.String(), wrongPassword.Body.String())
	}

	created := request(t, mux, "/api/signup", `{"email":"new@example.com","password":"long enough password"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("initial signup status = %d, want %d", created.Code, http.StatusCreated)
	}
	conflict := request(t, mux, "/api/signup", `{"email":"new@example.com","password":"long enough password"}`)
	if conflict.Code != http.StatusBadRequest || conflict.Body.String() != `{"error":"could not create account with those details"}`+"\n" {
		t.Fatalf("signup conflict = (%d, %q), want generic bad request", conflict.Code, conflict.Body.String())
	}
}

func TestLoginAuditEventsContainOutcomeAndSafeContext(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(&store.User{ID: "user-1", Email: "person@example.com", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	api := New(&auth.Service{Store: s}, s, s, s, s, s, s)

	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"email":"person@example.com","password":"wrong password"}`))
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("User-Agent", "audit-test")
	req.Header.Set("Authorization", "Bearer should-not-be-recorded")
	res := httptest.NewRecorder()
	api.handleLogin(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusUnauthorized)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"email":"person@example.com","password":"correct horse battery staple"}`))
	res = httptest.NewRecorder()
	api.handleLogin(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("successful login status = %d, want %d", res.Code, http.StatusOK)
	}

	events := s.ListAuditEvents()
	if len(events) != 2 {
		t.Fatalf("audit event count = %d, want 2", len(events))
	}
	if events[0].Type != "login" || events[0].Outcome != "failure" {
		t.Fatalf("first event = %+v, want failed login", events[0])
	}
	if events[1].Type != "login" || events[1].Outcome != "success" {
		t.Fatalf("second event = %+v, want successful login", events[1])
	}
	if events[0].ClientIP != "192.0.2.10:1234" || events[0].UserAgent != "audit-test" {
		t.Fatalf("failed login client context = %+v", events[0])
	}
	for _, event := range events {
		if event.ActorID != "user-1" || event.ActorEmail != "person@example.com" {
			t.Fatalf("event actor context = %+v", event)
		}
		if strings.Contains(string(mustJSON(event)), "wrong password") || strings.Contains(string(mustJSON(event)), "should-not-be-recorded") {
			t.Fatal("audit event contains request secrets")
		}
	}
}

func TestSignupAuditEventsRecordSuccessAndFailure(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	api := New(&auth.Service{Store: s}, s, s, s, s, s, s)

	for _, body := range []string{
		`{"email":"new@example.com","password":"correct horse battery staple"}`,
		`{"email":"new@example.com","password":"another safe password"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/signup", strings.NewReader(body))
		res := httptest.NewRecorder()
		api.handleSignup(res, req)
	}

	events := s.ListAuditEvents()
	if len(events) != 2 {
		t.Fatalf("audit event count = %d, want 2", len(events))
	}
	if events[0].Type != "signup" || events[0].Outcome != "success" {
		t.Fatalf("first event = %+v, want successful signup", events[0])
	}
	if events[1].Type != "signup" || events[1].Outcome != "failure" {
		t.Fatalf("second event = %+v, want failed signup", events[1])
	}
}

func mustJSON(v any) []byte {
	// The test only needs a serialization-independent secret check.
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
