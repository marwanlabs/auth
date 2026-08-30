package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"net/url"
	"time"

	"authserver/internal/providers"
	"authserver/internal/store"
)

const (
	socialStateCookiePrefix = "social_oauth_"
	socialTransactionTTL    = 10 * time.Minute
)

func (api *API) RegisterSocialRoutes(mux *http.ServeMux) {
	for id, provider := range api.Providers {
		name, p := id, provider
		mux.HandleFunc("GET /api/auth/"+name, func(w http.ResponseWriter, r *http.Request) { api.handleSocialStart(w, r, p) })
		mux.HandleFunc("GET /api/auth/"+name+"/callback", func(w http.ResponseWriter, r *http.Request) { api.handleSocialCallback(w, r, p) })
		if name == "apple" {
			mux.HandleFunc("POST /api/auth/"+name+"/callback", func(w http.ResponseWriter, r *http.Request) { api.handleSocialCallback(w, r, p) })
		}
	}
}

func (api *API) handleSocialStart(w http.ResponseWriter, r *http.Request, provider providers.Provider) {
	if !api.providerEnabled(provider.ID()) {
		writeError(w, http.StatusServiceUnavailable, "social sign-in is not configured")
		return
	}
	if api.OAuth == nil {
		writeError(w, http.StatusInternalServerError, "could not start social sign-in")
		return
	}
	state, err := randomState()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start social sign-in")
		return
	}
	verifier, err := randomState()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start social sign-in")
		return
	}
	tx := &store.OAuthTransaction{ID: state, Provider: provider.ID(), PKCEVerifier: verifier, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(socialTransactionTTL)}
	if err := api.OAuth.CreateOAuthTransaction(tx); err != nil {
		writeError(w, http.StatusInternalServerError, "could not start social sign-in")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: socialStateCookiePrefix + state, Value: provider.ID(), Path: "/", HttpOnly: true, Secure: api.Auth.Secure, SameSite: http.SameSiteLaxMode, MaxAge: int(socialTransactionTTL.Seconds())})
	authorizationURL := ""
	if pkce, ok := provider.(providers.PKCEProvider); ok {
		authorizationURL = pkce.AuthorizationURLWithVerifier(state, verifier)
	} else {
		authorizationURL = provider.AuthorizationURL(state)
	}
	if authorizationURL == "" {
		_, _ = api.OAuth.ConsumeOAuthTransaction(state, provider.ID())
		clearSocialState(w, api.Auth.Secure, state)
		writeError(w, http.StatusServiceUnavailable, "social provider is unavailable")
		return
	}
	http.Redirect(w, r, authorizationURL, http.StatusFound)
}

func (api *API) handleSocialCallback(w http.ResponseWriter, r *http.Request, provider providers.Provider) {
	if !api.providerEnabled(provider.ID()) {
		socialError(w, "social sign-in is not configured")
		return
	}
	state := r.FormValue("state")
	if api.OAuth == nil || state == "" {
		socialError(w, "invalid sign-in state")
		return
	}
	cookie, err := r.Cookie(socialStateCookiePrefix + state)
	if err != nil || cookie.Value != provider.ID() {
		socialError(w, "invalid sign-in state")
		return
	}
	tx, err := api.OAuth.ConsumeOAuthTransaction(state, provider.ID())
	if err != nil {
		socialError(w, "invalid sign-in state")
		return
	}
	clearSocialState(w, api.Auth.Secure, state)
	if r.FormValue("error") != "" {
		socialError(w, "social sign-in was cancelled")
		return
	}
	var identity providers.Identity
	var resolveErr error
	if pkce, ok := provider.(providers.PKCEProvider); ok {
		identity, resolveErr = pkce.ResolveWithVerifier(r.Context(), r.FormValue("code"), tx.PKCEVerifier)
	} else {
		identity, resolveErr = provider.Resolve(r.Context(), r.FormValue("code"))
	}
	if resolveErr != nil || identity.Subject == "" || !identity.EmailVerified || !looksLikeEmail(normalizeEmail(identity.Email)) {
		log.Printf("%s profile lookup: %v", provider.ID(), resolveErr)
		socialError(w, "the provider did not provide a verified email address")
		return
	}
	u, err := api.Social.Resolve(identity)
	if err != nil || u.Disabled {
		socialError(w, "could not sign in with this account")
		return
	}
	if err := api.Auth.SetSessionCookie(w, r, u.ID); err != nil {
		socialError(w, "could not start your session")
		return
	}
	http.Redirect(w, r, "/dashboard.html", http.StatusFound)
}

func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func socialError(w http.ResponseWriter, message string) {
	http.Redirect(w, &http.Request{URL: &url.URL{}}, "/login.html?oauth_error="+url.QueryEscape(message), http.StatusFound)
}

func clearSocialState(w http.ResponseWriter, secure bool, state string) {
	http.SetCookie(w, &http.Cookie{Name: socialStateCookiePrefix + state, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}

var _ store.OAuthTransactionRepository = (*store.Store)(nil)
