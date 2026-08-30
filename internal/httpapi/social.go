package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"net/url"

	"authserver/internal/providers"
)

const socialStateCookie = "social_oauth_state"

func (api *API) RegisterSocialRoutes(mux *http.ServeMux) {
	for id, provider := range api.Providers {
		name := id
		p := provider
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
	state, err := randomState()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start social sign-in")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: socialStateCookie, Value: state, Path: "/", HttpOnly: true, Secure: api.Auth.Secure, SameSite: http.SameSiteLaxMode, MaxAge: 10 * 60})
	authorizationURL := provider.AuthorizationURL(state)
	if authorizationURL == "" {
		clearSocialState(w, api.Auth.Secure)
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
	cookie, err := r.Cookie(socialStateCookie)
	if err != nil || cookie.Value == "" || cookie.Value != r.FormValue("state") {
		socialError(w, "invalid sign-in state")
		return
	}
	clearSocialState(w, api.Auth.Secure)
	if r.FormValue("error") != "" {
		socialError(w, "social sign-in was cancelled")
		return
	}
	state := r.FormValue("state")
	var identity providers.Identity
	var resolveErr error
	if stateful, ok := provider.(providers.StatefulProvider); ok {
		identity, resolveErr = stateful.ResolveWithState(r.Context(), r.FormValue("code"), state)
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
	http.Redirect(w, &http.Request{}, "/login.html?oauth_error="+url.QueryEscape(message), http.StatusFound)
}
func clearSocialState(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: socialStateCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}
