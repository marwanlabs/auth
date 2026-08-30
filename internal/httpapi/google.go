package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"authserver/internal/auth"
	"authserver/internal/store"
	"golang.org/x/oauth2"
)

const socialStateCookie = "social_oauth_state"

type OAuthProvider struct {
	Config      oauth2.Config
	Secure      bool
	Name        string
	UserInfoURL string
}

type GoogleOAuth = OAuthProvider

func (api *API) RegisterGoogle(mux *http.ServeMux) { api.registerProvider(mux, "google", api.Google) }
func (api *API) RegisterFacebook(mux *http.ServeMux) {
	api.registerProvider(mux, "facebook", api.Facebook)
}

func (api *API) registerProvider(mux *http.ServeMux, name string, provider *OAuthProvider) {
	mux.HandleFunc("GET /api/auth/"+name, func(w http.ResponseWriter, r *http.Request) { api.handleOAuthStart(w, r, provider) })
	mux.HandleFunc("GET /api/auth/"+name+"/callback", func(w http.ResponseWriter, r *http.Request) { api.handleOAuthCallback(w, r, provider) })
}

func (api *API) handleOAuthStart(w http.ResponseWriter, r *http.Request, provider *OAuthProvider) {
	if !oauthConfigured(provider) || !api.providerEnabled(provider.Name) {
		writeError(w, http.StatusServiceUnavailable, "social sign-in is not configured")
		return
	}
	state, err := auth.NewToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start social sign-in")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: socialStateCookie, Value: state, Path: "/", HttpOnly: true, Secure: provider.Secure, SameSite: http.SameSiteLaxMode, MaxAge: 10 * 60})
	http.Redirect(w, r, provider.Config.AuthCodeURL(state, oauth2.AccessTypeOnline), http.StatusFound)
}

func (api *API) handleOAuthCallback(w http.ResponseWriter, r *http.Request, provider *OAuthProvider) {
	if !oauthConfigured(provider) || !api.providerEnabled(provider.Name) {
		oauthError(w, "social sign-in is not configured")
		return
	}
	stateCookie, err := r.Cookie(socialStateCookie)
	if err != nil || stateCookie.Value == "" || r.URL.Query().Get("state") != stateCookie.Value {
		oauthError(w, "invalid sign-in state")
		return
	}
	clearOAuthStateCookie(w, provider.Secure)
	if r.URL.Query().Get("error") != "" {
		oauthError(w, "social sign-in was cancelled")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		oauthError(w, "social sign-in did not return a code")
		return
	}
	token, err := provider.Config.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("%s token exchange: %v", provider.Name, err)
		oauthError(w, "social sign-in failed")
		return
	}
	profile, err := fetchOAuthProfile(r, provider, provider.Config.Client(r.Context(), token))
	if err != nil || profile.Sub == "" || !profile.EmailVerified || !looksLikeEmail(normalizeEmail(profile.Email)) {
		log.Printf("%s profile lookup: %v", provider.Name, err)
		oauthError(w, "the provider did not provide a verified email address")
		return
	}

	identity, err := api.Store.GetIdentity(provider.Name, profile.Sub)
	var u *store.User
	if err == nil {
		u, err = api.Store.GetUserByID(identity.UserID)
	} else if err == store.ErrNotFound {
		if provider.Name == "google" {
			u, err = api.Store.GetUserByGoogleID(profile.Sub)
			if err == nil {
				err = api.Store.CreateIdentity(&store.SocialIdentity{ID: mustID(), Provider: provider.Name, Subject: profile.Sub, UserID: u.ID, CreatedAt: time.Now()})
				if err == store.ErrConflict {
					err = nil
				}
			}
		}
		if err == nil { /* existing Google identity was migrated above */
		} else if err == store.ErrNotFound {
			u, err = api.Store.GetUserByEmail(normalizeEmail(profile.Email))
			if err == store.ErrNotFound {
				role := store.RoleUser
				if api.Store.CountUsers() == 0 {
					role = store.RoleAdmin
				}
				u = &store.User{ID: mustID(), Email: normalizeEmail(profile.Email), Role: role, CreatedAt: time.Now()}
				err = api.Store.CreateUser(u)
				if err == store.ErrConflict {
					u, err = api.Store.GetUserByEmail(normalizeEmail(profile.Email))
				}
			}
			if err == nil && u != nil {
				err = api.Store.CreateIdentity(&store.SocialIdentity{ID: mustID(), Provider: provider.Name, Subject: profile.Sub, UserID: u.ID, CreatedAt: time.Now()})
				if err == store.ErrConflict {
					err = nil
				}
			}
		}
	}
	if err != nil || u == nil {
		oauthError(w, "could not create or link your account")
		return
	}
	if u.Disabled {
		oauthError(w, "this account is disabled")
		return
	}
	if err := api.Auth.SetSessionCookie(w, r, u.ID); err != nil {
		oauthError(w, "could not start your session")
		return
	}
	http.Redirect(w, r, "/dashboard.html", http.StatusFound)
}

type oauthProfile struct {
	Sub           string `json:"sub"`
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func fetchOAuthProfile(r *http.Request, provider *OAuthProvider, client *http.Client) (*oauthProfile, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, provider.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned %s", resp.Status)
	}
	var profile oauthProfile
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&profile); err != nil {
		return nil, err
	}
	if profile.Sub == "" {
		profile.Sub = profile.ID
	}
	if provider.Name == "facebook" {
		profile.EmailVerified = profile.Email != ""
	}
	return &profile, nil
}

func oauthConfigured(provider *OAuthProvider) bool {
	return provider != nil && provider.Name != "" && provider.UserInfoURL != "" && provider.Config.ClientID != "" && provider.Config.ClientSecret != "" && provider.Config.Endpoint.AuthURL != ""
}

func oauthError(w http.ResponseWriter, message string) {
	http.Redirect(w, &http.Request{}, "/login.html?oauth_error="+url.QueryEscape(message), http.StatusFound)
}

func clearOAuthStateCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: socialStateCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}
