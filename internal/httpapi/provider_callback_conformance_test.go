package httpapi

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"authserver/internal/providers"
)

func TestOAuthProviderConformanceAppleFormPost(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idToken := testJWT(t, key, map[string]any{
		"iss": "https://appleid.apple.com", "aud": "apple-client", "sub": "apple-subject",
		"exp": time.Now().Add(time.Hour).Unix(), "email": "apple@example.com", "email_verified": true,
	})

	network := newProviderNetwork(t, map[string]func(*http.Request) (int, string){
		"https://appleid.apple.com/auth/token": func(r *http.Request) (int, string) {
			if r.Method != http.MethodPost {
				t.Fatalf("Apple token method = %s, want POST", r.Method)
			}
			return http.StatusOK, `{"access_token":"token","id_token":"` + idToken + `","token_type":"Bearer"}`
		},
		"https://appleid.apple.com/auth/keys": func(*http.Request) (int, string) {
			return http.StatusOK, fmt.Sprintf(`{"keys":[{"kid":"test-key","kty":"RSA","n":"%s","e":"AQAB"}]}`,
				base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()))
		},
	})
	defer network.Close()

	_, db, mux := testMux(t, providers.NewApple("apple-client", "apple-secret", "http://localhost/callback"))
	start := httptest.NewRecorder()
	mux.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/api/auth/apple", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("start status = %d, want %d", start.Code, http.StatusFound)
	}
	authorize, err := url.Parse(start.Header().Get("Location"))
	if err != nil || authorize.Query().Get("response_mode") != "form_post" {
		t.Fatalf("Apple authorization URL = %q, missing form_post", start.Header().Get("Location"))
	}
	cookie := start.Result().Cookies()[0]
	state := strings.TrimPrefix(cookie.Name, socialStateCookiePrefix)
	callback := httptest.NewRequest(http.MethodPost, "/api/auth/apple/callback", strings.NewReader(url.Values{
		"state": {state}, "code": {"apple-code"},
	}.Encode()))
	callback.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	callback.AddCookie(cookie)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, callback)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/dashboard.html" {
		t.Fatalf("Apple callback = %d %q, want dashboard redirect", response.Code, response.Header().Get("Location"))
	}
	if _, err := db.GetIdentity("apple", "apple-subject"); err != nil {
		t.Fatalf("Apple identity was not persisted: %v", err)
	}
}

func TestOAuthProviderConformanceOIDCDiscoveryAndProfile(t *testing.T) {
	network := newProviderNetwork(t, map[string]func(*http.Request) (int, string){
		"https://oidc.test/.well-known/openid-configuration": func(*http.Request) (int, string) {
			return http.StatusOK, `{"authorization_endpoint":"https://oidc.test/authorize","token_endpoint":"https://oidc.test/token","userinfo_endpoint":"https://oidc.test/userinfo"}`
		},
		"https://oidc.test/token": func(r *http.Request) (int, string) {
			if r.FormValue("code") != "oidc-code" {
				t.Fatalf("OIDC token code = %q", r.FormValue("code"))
			}
			return http.StatusOK, `{"access_token":"oidc-token","token_type":"Bearer"}`
		},
		"https://oidc.test/userinfo": func(*http.Request) (int, string) {
			return http.StatusOK, `{"sub":"oidc-subject","email":"oidc@example.com","email_verified":true}`
		},
	})
	defer network.Close()

	_, db, mux := testMux(t, providers.NewOIDC("https://oidc.test", "oidc-client", "oidc-secret", "http://localhost/callback"))
	start := httptest.NewRecorder()
	mux.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/api/auth/oidc", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("OIDC start = %d, want %d", start.Code, http.StatusFound)
	}
	authorize, err := url.Parse(start.Header().Get("Location"))
	if err != nil || authorize.Host != "oidc.test" || authorize.Query().Get("client_id") != "oidc-client" {
		t.Fatalf("OIDC authorization URL = %q", start.Header().Get("Location"))
	}
	callbackWithCookie(t, mux, "oidc", start.Result().Cookies()[0], http.MethodGet, url.Values{"code": {"oidc-code"}})
	if _, err := db.GetIdentity("oidc", "oidc-subject"); err != nil {
		t.Fatalf("OIDC identity was not persisted: %v", err)
	}
}

func TestOAuthProviderConformanceTwitterPKCEFailureConsumesTransaction(t *testing.T) {
	var receivedVerifier string
	network := newProviderNetwork(t, map[string]func(*http.Request) (int, string){
		"https://twitter.com/i/oauth2/authorize": func(*http.Request) (int, string) { return http.StatusOK, `{}` },
		"https://api.x.com/2/oauth2/token": func(r *http.Request) (int, string) {
			receivedVerifier = r.FormValue("code_verifier")
			return http.StatusOK, `{"access_token":"twitter-token","token_type":"Bearer"}`
		},
		"https://api.x.com/2/users/me?user.fields=id,confirmed_email": func(*http.Request) (int, string) {
			return http.StatusOK, `{"data":{"id":"twitter-subject"}}`
		},
	})
	defer network.Close()

	_, _, mux := testMux(t, providers.NewTwitter("twitter-client", "twitter-secret", "http://localhost/callback"))
	start := httptest.NewRecorder()
	mux.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/api/auth/twitter", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("Twitter start = %d, want %d", start.Code, http.StatusFound)
	}
	authorize, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	challenge := authorize.Query().Get("code_challenge")
	if challenge == "" || challenge == authorize.Query().Get("state") {
		t.Fatalf("Twitter PKCE challenge = %q, state = %q", challenge, authorize.Query().Get("state"))
	}
	cookie := start.Result().Cookies()[0]
	state := strings.TrimPrefix(cookie.Name, socialStateCookiePrefix)
	response := httptest.NewRecorder()
	callback := httptest.NewRequest(http.MethodGet, "/api/auth/twitter/callback?state="+url.QueryEscape(state)+"&code=twitter-code", nil)
	callback.AddCookie(cookie)
	mux.ServeHTTP(response, callback)
	if response.Code != http.StatusFound || !strings.Contains(response.Header().Get("Location"), "verified+email+address") {
		t.Fatalf("Twitter failure = %d %q", response.Code, response.Header().Get("Location"))
	}
	if receivedVerifier == "" {
		t.Fatal("Twitter callback did not send the stored PKCE verifier")
	}
	digest := sha256.Sum256([]byte(receivedVerifier))
	if got := base64.RawURLEncoding.EncodeToString(digest[:]); got != challenge {
		t.Fatalf("Twitter challenge = %q, verifier produces %q", challenge, got)
	}
	replay := httptest.NewRecorder()
	mux.ServeHTTP(replay, callback)
	if !strings.Contains(replay.Header().Get("Location"), "invalid+sign-in+state") {
		t.Fatalf("Twitter replay = %q", replay.Header().Get("Location"))
	}
}

func callbackWithCookie(t *testing.T, mux *http.ServeMux, provider string, cookie *http.Cookie, method string, values url.Values) {
	t.Helper()
	state := strings.TrimPrefix(cookie.Name, socialStateCookiePrefix)
	values.Set("state", state)
	path := "/api/auth/" + provider + "/callback?" + values.Encode()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, nil)
	request.AddCookie(cookie)
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/dashboard.html" {
		t.Fatalf("%s callback = %d %q", provider, response.Code, response.Header().Get("Location"))
	}
}

type providerNetwork struct {
	server *httptest.Server
	old    http.RoundTripper
}

func newProviderNetwork(t *testing.T, handlers map[string]func(*http.Request) (int, string)) *providerNetwork {
	network := &providerNetwork{}
	network.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler, ok := handlers[r.Header.Get("X-Test-Provider-URL")]
		if !ok {
			http.Error(w, "unexpected provider request", http.StatusNotFound)
			return
		}
		status, body := handler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	network.old = http.DefaultTransport
	http.DefaultTransport = roundTripProviderRequests{next: network.old, serverURL: network.server.URL}
	return network
}

func (n *providerNetwork) Close() {
	http.DefaultTransport = n.old
	n.server.Close()
}

type roundTripProviderRequests struct {
	next      http.RoundTripper
	serverURL string
}

func (t roundTripProviderRequests) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Host, "appleid.apple.com") || strings.HasSuffix(r.URL.Host, "oidc.test") || strings.HasSuffix(r.URL.Host, "twitter.com") || strings.HasSuffix(r.URL.Host, "api.x.com") {
		clone := r.Clone(r.Context())
		clone.Header.Set("X-Test-Provider-URL", r.URL.String())
		clone.URL.Scheme = "http"
		clone.URL.Host = strings.TrimPrefix(t.serverURL, "http://")
		return t.next.RoundTrip(clone)
	}
	return t.next.RoundTrip(r)
}

func testJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test-key"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := header + "." + encodedPayload
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}
