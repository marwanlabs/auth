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

const googleStateCookie = "google_oauth_state"

// GoogleOAuth contains the server-side settings for Google sign-in.
// Leave it nil to disable the feature.
type GoogleOAuth struct {
	Config oauth2.Config
	Secure bool
}

func (api *API) RegisterGoogle(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/auth/google", api.handleGoogleStart)
	mux.HandleFunc("GET /api/auth/google/callback", api.handleGoogleCallback)
}

func (api *API) handleGoogleStart(w http.ResponseWriter, r *http.Request) {
	if !api.googleConfigured() {
		writeError(w, http.StatusServiceUnavailable, "Google sign-in is not configured")
		return
	}
	state, err := auth.NewToken(32)
	if err != nil {
		http.Error(w, "could not start Google sign-in", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: googleStateCookie, Value: state, Path: "/", HttpOnly: true,
		Secure: api.Google.Secure, SameSite: http.SameSiteLaxMode,
		MaxAge: 10 * 60,
	})
	http.Redirect(w, r, api.Google.Config.AuthCodeURL(state, oauth2.AccessTypeOnline), http.StatusFound)
}

func (api *API) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if !api.googleConfigured() {
		api.googleError(w, "Google sign-in is not configured")
		return
	}
	stateCookie, err := r.Cookie(googleStateCookie)
	if err != nil || stateCookie.Value == "" || r.URL.Query().Get("state") != stateCookie.Value {
		api.googleError(w, "invalid sign-in state")
		return
	}
	clearOAuthStateCookie(w, api.Google.Secure)
	if r.URL.Query().Get("error") != "" {
		api.googleError(w, "Google sign-in was cancelled")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		api.googleError(w, "Google sign-in did not return a code")
		return
	}

	token, err := api.Google.Config.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("Google token exchange: %v", err)
		api.googleError(w, "Google sign-in failed")
		return
	}
	profile, err := fetchGoogleProfile(r, api.Google.Config.Client(r.Context(), token))
	if err != nil || profile.Sub == "" || !profile.EmailVerified || !looksLikeEmail(normalizeEmail(profile.Email)) {
		log.Printf("Google profile lookup: %v", err)
		api.googleError(w, "Google did not provide a verified email address")
		return
	}

	u, err := api.Store.GetUserByGoogleID(profile.Sub)
	if err == store.ErrNotFound {
		u, err = api.Store.GetUserByEmail(normalizeEmail(profile.Email))
		if err == store.ErrNotFound {
			role := store.RoleUser
			if api.Store.CountUsers() == 0 {
				role = store.RoleAdmin
			}
			u = &store.User{ID: mustID(), Email: normalizeEmail(profile.Email), GoogleID: profile.Sub, Role: role, CreatedAt: time.Now()}
			if err = api.Store.CreateUser(u); err != nil && err == store.ErrConflict {
				u, err = api.Store.GetUserByEmail(normalizeEmail(profile.Email))
				if err == nil && u.GoogleID == "" {
					u.GoogleID = profile.Sub
					err = api.Store.UpdateUser(u)
				}
			}
		} else if err == nil {
			if u.GoogleID != "" && u.GoogleID != profile.Sub {
				api.googleError(w, "that email is linked to another Google account")
				return
			}
			u.GoogleID = profile.Sub
			err = api.Store.UpdateUser(u)
		}
	}
	if err != nil || u == nil {
		api.googleError(w, "could not create or link your account")
		return
	}
	if u.Disabled {
		api.googleError(w, "this account is disabled")
		return
	}
	if err := api.Auth.SetSessionCookie(w, r, u.ID); err != nil {
		api.googleError(w, "could not start your session")
		return
	}
	http.Redirect(w, r, "/dashboard.html", http.StatusFound)
}

func (api *API) googleConfigured() bool {
	return api.Google != nil && api.Google.Config.ClientID != "" && api.Google.Config.ClientSecret != "" && api.Google.Config.Endpoint.AuthURL != ""
}

type googleProfile struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func fetchGoogleProfile(r *http.Request, client *http.Client) (*googleProfile, error) {
	req, err := http.NewRequest(http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req.WithContext(r.Context()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned %s", resp.Status)
	}
	var profile googleProfile
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&profile)
	return &profile, err
}

func (api *API) googleError(w http.ResponseWriter, message string) {
	http.Redirect(w, &http.Request{}, "/login.html?oauth_error="+url.QueryEscape(message), http.StatusFound)
}

func clearOAuthStateCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: googleStateCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}
