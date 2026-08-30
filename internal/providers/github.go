package providers

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
)

func NewGitHub(clientID, clientSecret, redirectURL string) Provider {
	return &oauthAdapter{
		id: "github", name: "GitHub", profileURL: "https://api.github.com/user",
		config: oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL, Endpoint: oauth2.Endpoint{AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token"}, Scopes: []string{"user:email"}},
		resolveProfile: func(ctx context.Context, client *http.Client) (Identity, error) {
			var p struct {
				ID    int64  `json:"id"`
				Email string `json:"email"`
			}
			if err := fetchProfile(ctx, client, "https://api.github.com/user", &p); err != nil {
				return Identity{}, err
			}
			if p.Email == "" {
				var emails []struct {
					Email    string `json:"email"`
					Primary  bool   `json:"primary"`
					Verified bool   `json:"verified"`
				}
				if err := fetchProfile(ctx, client, "https://api.github.com/user/emails", &emails); err != nil {
					return Identity{}, err
				}
				for _, email := range emails {
					if email.Primary && email.Verified {
						p.Email = email.Email
						break
					}
				}
			}
			if p.Email == "" {
				return Identity{}, fmt.Errorf("GitHub has no verified primary email")
			}
			return Identity{Provider: "github", Subject: fmt.Sprint(p.ID), Email: p.Email, EmailVerified: true}, nil
		},
	}
}
