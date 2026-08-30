package providers

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// NewGitLab creates a GitLab.com OAuth provider. A self-managed GitLab
// instance can be supported later by making the endpoint base configurable.
func NewGitLab(clientID, clientSecret, redirectURL string) Provider {
	return &oauthAdapter{
		id: "gitlab", name: "GitLab", profileURL: "https://gitlab.com/api/v4/user",
		config: oauth2.Config{
			ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://gitlab.com/oauth/authorize",
				TokenURL: "https://gitlab.com/oauth/token",
			},
			Scopes: []string{"read_user", "email"},
		},
		resolveProfile: func(ctx context.Context, client *http.Client) (Identity, error) {
			var profile struct {
				ID          int64  `json:"id"`
				Email       string `json:"email"`
				PublicEmail string `json:"public_email"`
			}
			if err := fetchProfile(ctx, client, "https://gitlab.com/api/v4/user", &profile); err != nil {
				return Identity{}, err
			}
			email := profile.Email
			if email == "" {
				email = profile.PublicEmail
			}
			if profile.ID == 0 || email == "" {
				return Identity{}, fmt.Errorf("GitLab profile has no email")
			}
			return Identity{Provider: "gitlab", Subject: fmt.Sprint(profile.ID), Email: email, EmailVerified: true}, nil
		},
	}
}
