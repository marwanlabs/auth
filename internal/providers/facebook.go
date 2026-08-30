package providers

import (
	"context"
	"golang.org/x/oauth2"
	"net/http"
)

func NewFacebook(clientID, clientSecret, redirectURL string) Provider {
	return &oauthAdapter{
		id: "facebook", name: "Facebook", profileURL: "https://graph.facebook.com/me?fields=id,email",
		config: oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL, Endpoint: oauth2.Endpoint{AuthURL: "https://www.facebook.com/v19.0/dialog/oauth", TokenURL: "https://graph.facebook.com/v19.0/oauth/access_token"}, Scopes: []string{"email"}},
		resolveProfile: func(ctx context.Context, client *http.Client) (Identity, error) {
			var p struct {
				ID    string `json:"id"`
				Email string `json:"email"`
			}
			if err := fetchProfile(ctx, client, "https://graph.facebook.com/me?fields=id,email", &p); err != nil {
				return Identity{}, err
			}
			return Identity{Provider: "facebook", Subject: p.ID, Email: p.Email, EmailVerified: p.Email != ""}, nil
		},
	}
}
