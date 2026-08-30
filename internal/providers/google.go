package providers

import (
	"context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
	"net/http"
)

func NewGoogle(clientID, clientSecret, redirectURL string) Provider {
	return &oauthAdapter{
		id: "google", name: "Google", profileURL: "https://openidconnect.googleapis.com/v1/userinfo",
		config: oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL, Endpoint: endpoints.Google, Scopes: []string{"openid", "email", "profile"}},
		resolveProfile: func(ctx context.Context, client *http.Client) (Identity, error) {
			var p struct {
				Sub      string `json:"sub"`
				Email    string `json:"email"`
				Verified bool   `json:"email_verified"`
			}
			if err := fetchProfile(ctx, client, "https://openidconnect.googleapis.com/v1/userinfo", &p); err != nil {
				return Identity{}, err
			}
			return Identity{Provider: "google", Subject: p.Sub, Email: p.Email, EmailVerified: p.Verified}, nil
		},
	}
}
