package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"authserver/internal/auth"
	"authserver/internal/providers"
	"authserver/internal/store"
)

type conformanceProvider struct {
	id         string
	configured bool
	identity   providers.Identity
	resolveErr error
}

type expiredOAuthRepository struct{}

func (expiredOAuthRepository) CreateOAuthTransaction(*store.OAuthTransaction) error { return nil }
func (expiredOAuthRepository) ConsumeOAuthTransaction(string, string) (*store.OAuthTransaction, error) {
	return nil, store.ErrNotFound
}

func (p *conformanceProvider) ID() string       { return p.id }
func (p *conformanceProvider) Name() string     { return p.id }
func (p *conformanceProvider) Configured() bool { return p.configured }
func (p *conformanceProvider) AuthorizationURL(state string) string {
	return "https://oauth.test/authorize?state=" + url.QueryEscape(state)
}
func (p *conformanceProvider) Resolve(context.Context, string) (providers.Identity, error) {
	return p.identity, p.resolveErr
}

// identityStore is the minimal persistence capability the conformance test
// observes to verify that a completed sign-in linked the social identity.
type identityStore interface {
	GetIdentity(provider, subject string) (*store.SocialIdentity, error)
}

func testConformanceAPI(t testing.TB) (*API, identityStore) {
	t.Helper()
	s, err := store.Open(t.TempDir() + "/store.json")
	if err != nil {
		t.Fatal(err)
	}
	return New(&auth.Service{Store: s}, s, s, s, s, s, s, s), s
}

func testMux(t testing.TB, provider providers.Provider) (*API, identityStore, *http.ServeMux) {
	t.Helper()
	api, db := testConformanceAPI(t)
	api.Providers[provider.ID()] = provider
	if provider.Configured() {
		if err := api.ProviderDB.SetProviderEnabled(provider.ID(), true); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	api.Register(mux)
	api.RegisterSocialRoutes(mux)
	return api, db, mux
}

func supportedProviderIDs() []string {
	ids := make([]string, 0, len(supportedProviders))
	for _, provider := range supportedProviders {
		ids = append(ids, provider.ID)
	}
	return ids
}

func TestOAuthProviderConformance(t *testing.T) {
	for _, id := range supportedProviderIDs() {
		t.Run(id+" success", func(t *testing.T) {
			provider := &conformanceProvider{id: id, configured: true, identity: providers.Identity{
				Provider: id, Subject: "subject-" + id, Email: " Person@Example.COM ", EmailVerified: true,
			}}
			_, db, mux := testMux(t, provider)
			start := httptest.NewRequest(http.MethodGet, "/api/auth/"+id, nil)
			startResponse := httptest.NewRecorder()
			mux.ServeHTTP(startResponse, start)
			if startResponse.Code != http.StatusFound {
				t.Fatalf("start status = %d, want %d", startResponse.Code, http.StatusFound)
			}
			stateCookie := startResponse.Result().Cookies()[0]
			state := strings.TrimPrefix(stateCookie.Name, socialStateCookiePrefix)
			if state == "" {
				t.Fatal("start did not issue state cookie")
			}

			callback := httptest.NewRequest(http.MethodGet, "/api/auth/"+id+"/callback?state="+url.QueryEscape(state)+"&code=code", nil)
			callback.AddCookie(stateCookie)
			callbackResponse := httptest.NewRecorder()
			mux.ServeHTTP(callbackResponse, callback)
			if callbackResponse.Code != http.StatusFound || callbackResponse.Header().Get("Location") != "/dashboard.html" {
				t.Fatalf("callback = %d %q, want dashboard redirect", callbackResponse.Code, callbackResponse.Header().Get("Location"))
			}
			if _, err := db.GetIdentity(id, "subject-"+id); err != nil {
				t.Fatalf("identity was not persisted: %v", err)
			}
			var sessionCookie *http.Cookie
			for _, cookie := range callbackResponse.Result().Cookies() {
				if cookie.Name == auth.SessionCookieName {
					sessionCookie = cookie
				}
			}
			if sessionCookie == nil {
				t.Fatal("callback did not issue session cookie")
			}
			me := httptest.NewRequest(http.MethodGet, "/api/me", nil)
			me.AddCookie(sessionCookie)
			meResponse := httptest.NewRecorder()
			mux.ServeHTTP(meResponse, me)
			if meResponse.Code != http.StatusOK {
				t.Fatalf("session check status = %d, want %d", meResponse.Code, http.StatusOK)
			}
		})

		t.Run(id+" cancellation", func(t *testing.T) {
			provider := &conformanceProvider{id: id, configured: true}
			_, _, mux := testMux(t, provider)
			startResponse := httptest.NewRecorder()
			mux.ServeHTTP(startResponse, httptest.NewRequest(http.MethodGet, "/api/auth/"+id, nil))
			stateCookie := startResponse.Result().Cookies()[0]
			state := strings.TrimPrefix(stateCookie.Name, socialStateCookiePrefix)
			callback := httptest.NewRequest(http.MethodGet, "/api/auth/"+id+"/callback?state="+url.QueryEscape(state)+"&error=access_denied", nil)
			callback.AddCookie(stateCookie)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, callback)
			if response.Code != http.StatusFound || !strings.Contains(response.Header().Get("Location"), "social+sign-in+was+cancelled") {
				t.Fatalf("cancellation = %d %q", response.Code, response.Header().Get("Location"))
			}
			replay := httptest.NewRecorder()
			mux.ServeHTTP(replay, callback)
			if !strings.Contains(replay.Header().Get("Location"), "invalid+sign-in+state") {
				t.Fatalf("cancelled replay = %q", replay.Header().Get("Location"))
			}
		})

		t.Run(id+" invalid email", func(t *testing.T) {
			provider := &conformanceProvider{id: id, configured: true, identity: providers.Identity{Provider: id, Subject: "subject", Email: "not-an-email", EmailVerified: true}}
			_, _, mux := testMux(t, provider)
			startResponse := httptest.NewRecorder()
			mux.ServeHTTP(startResponse, httptest.NewRequest(http.MethodGet, "/api/auth/"+id, nil))
			stateCookie := startResponse.Result().Cookies()[0]
			state := strings.TrimPrefix(stateCookie.Name, socialStateCookiePrefix)
			callback := httptest.NewRequest(http.MethodGet, "/api/auth/"+id+"/callback?state="+url.QueryEscape(state)+"&code=code", nil)
			callback.AddCookie(stateCookie)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, callback)
			if response.Code != http.StatusFound || !strings.Contains(response.Header().Get("Location"), "verified+email+address") {
				t.Fatalf("invalid email = %d %q", response.Code, response.Header().Get("Location"))
			}
		})

		t.Run(id+" unavailable", func(t *testing.T) {
			provider := &conformanceProvider{id: id}
			_, _, mux := testMux(t, provider)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/auth/"+id, nil))
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("unavailable = %d, want %d", response.Code, http.StatusServiceUnavailable)
			}
		})
	}
}

func TestOAuthCallbackRejectsInvalidState(t *testing.T) {
	provider := &conformanceProvider{id: "google", configured: true}
	_, _, mux := testMux(t, provider)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state=wrong&code=code", nil))
	if response.Code != http.StatusFound || !strings.Contains(response.Header().Get("Location"), "invalid+sign-in+state") {
		t.Fatalf("invalid state = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestOAuthCallbackRejectsProviderMismatchedCookie(t *testing.T) {
	provider := &conformanceProvider{id: "google", configured: true}
	_, _, mux := testMux(t, provider)
	startResponse := httptest.NewRecorder()
	mux.ServeHTTP(startResponse, httptest.NewRequest(http.MethodGet, "/api/auth/google", nil))
	cookie := startResponse.Result().Cookies()[0]
	state := strings.TrimPrefix(cookie.Name, socialStateCookiePrefix)
	cookie.Value = "github"
	callback := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state="+url.QueryEscape(state)+"&code=code", nil)
	callback.AddCookie(cookie)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, callback)
	if response.Code != http.StatusFound || !strings.Contains(response.Header().Get("Location"), "invalid+sign-in+state") {
		t.Fatalf("provider mismatch = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestOAuthCallbackRejectsExpiredTransaction(t *testing.T) {
	provider := &conformanceProvider{id: "google", configured: true}
	api, _, mux := testMux(t, provider)
	startResponse := httptest.NewRecorder()
	mux.ServeHTTP(startResponse, httptest.NewRequest(http.MethodGet, "/api/auth/google", nil))
	stateCookie := startResponse.Result().Cookies()[0]
	state := strings.TrimPrefix(stateCookie.Name, socialStateCookiePrefix)
	api.OAuth = expiredOAuthRepository{}
	response := httptest.NewRecorder()
	callback := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state="+url.QueryEscape(state)+"&code=code", nil)
	callback.AddCookie(stateCookie)
	mux.ServeHTTP(response, callback)
	if response.Code != http.StatusFound || !strings.Contains(response.Header().Get("Location"), "invalid+sign-in+state") {
		t.Fatalf("expired state = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestOAuthCallbackRejectsProviderError(t *testing.T) {
	provider := &conformanceProvider{id: "google", configured: true, resolveErr: context.Canceled}
	_, _, mux := testMux(t, provider)
	startResponse := httptest.NewRecorder()
	mux.ServeHTTP(startResponse, httptest.NewRequest(http.MethodGet, "/api/auth/google", nil))
	stateCookie := startResponse.Result().Cookies()[0]
	state := strings.TrimPrefix(stateCookie.Name, socialStateCookiePrefix)
	callback := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state="+url.QueryEscape(state)+"&code=code", nil)
	callback.AddCookie(stateCookie)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, callback)
	if response.Code != http.StatusFound || !strings.Contains(response.Header().Get("Location"), "verified+email+address") {
		t.Fatalf("provider error = %d %q", response.Code, response.Header().Get("Location"))
	}
	replay := httptest.NewRecorder()
	mux.ServeHTTP(replay, callback)
	if !strings.Contains(replay.Header().Get("Location"), "invalid+sign-in+state") {
		t.Fatalf("failed replay = %q", replay.Header().Get("Location"))
	}
}

func TestOAuthTransactionsDoNotOverwriteParallelFlows(t *testing.T) {
	provider := &conformanceProvider{id: "google", configured: true, identity: providers.Identity{Provider: "google", Subject: "subject", Email: "person@example.com", EmailVerified: true}}
	_, _, mux := testMux(t, provider)
	first := httptest.NewRecorder()
	mux.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/auth/google", nil))
	second := httptest.NewRecorder()
	mux.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/api/auth/google", nil))
	firstCookie, secondCookie := first.Result().Cookies()[0], second.Result().Cookies()[0]
	if firstCookie.Name == secondCookie.Name {
		t.Fatal("parallel transactions used the same cookie")
	}
	firstState := strings.TrimPrefix(firstCookie.Name, socialStateCookiePrefix)
	secondState := strings.TrimPrefix(secondCookie.Name, socialStateCookiePrefix)
	for _, flow := range []struct {
		state  string
		cookie *http.Cookie
	}{
		{firstState, firstCookie}, {secondState, secondCookie},
	} {
		callback := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state="+url.QueryEscape(flow.state)+"&code=code", nil)
		callback.AddCookie(flow.cookie)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, callback)
		if response.Header().Get("Location") != "/dashboard.html" {
			t.Fatalf("parallel callback = %q", response.Header().Get("Location"))
		}
	}
}

func TestOAuthProviderListIncludesAllSupportedProviders(t *testing.T) {
	api, _ := testConformanceAPI(t)
	for _, id := range supportedProviderIDs() {
		api.Providers[id] = &conformanceProvider{id: id, configured: true}
	}
	mux := http.NewServeMux()
	api.RegisterProviderRoutes(mux)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/auth/providers", nil))
	var providersList []providerView
	if err := json.NewDecoder(response.Body).Decode(&providersList); err != nil {
		t.Fatal(err)
	}
	if len(providersList) != 2 {
		t.Fatalf("public provider list has %d entries, want default-enabled providers only", len(providersList))
	}
}
