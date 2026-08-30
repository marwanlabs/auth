package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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
	api := New(&auth.Service{Store: s}, s)
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
	if got := api.Store.CountUsers(); got != 10 {
		t.Fatalf("user count = %d, want 10", got)
	}
	sessions := 0
	for _, u := range api.Store.ListUsers() {
		userSessions, err := api.Store.ListSessionsForUser(u.ID)
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
	if got := len(api.Store.ListUsers()); got != 0 {
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
	if err := api.Store.CreateUser(&store.User{ID: "user-1", Email: "known@example.com", PasswordHash: hash, Role: store.RoleUser}); err != nil {
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
