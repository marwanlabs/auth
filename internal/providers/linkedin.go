package providers

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// NewLinkedIn creates a LinkedIn OpenID Connect provider.
func NewLinkedIn(clientID, clientSecret, redirectURL string) Provider {
	return &oauthAdapter{
		id: "linkedin", name: "LinkedIn", profileURL: "https://api.linkedin.com/v2/userinfo",
		config: oauth2.Config{
			ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://www.linkedin.com/oauth/v2/authorization",
				TokenURL: "https://www.linkedin.com/oauth/v2/accessToken",
			},
			Scopes: []string{"openid", "profile", "email"},
		},
		resolveProfile: func(ctx context.Context, client *http.Client) (Identity, error) {
			var profile struct {
				Subject       string `json:"sub"`
				Email         string `json:"email"`
				EmailVerified bool   `json:"email_verified"`
			}
			if err := fetchProfile(ctx, client, "https://api.linkedin.com/v2/userinfo", &profile); err != nil {
				return Identity{}, err
			}
			if profile.Subject == "" || profile.Email == "" {
				return Identity{}, fmt.Errorf("LinkedIn profile has no email")
			}
			return Identity{Provider: "linkedin", Subject: profile.Subject, Email: profile.Email, EmailVerified: profile.EmailVerified}, nil
		},
	}
}
