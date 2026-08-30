package providers

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// NewDiscord creates a Discord OAuth provider with access limited to the
// authenticated user's profile and email address.
func NewDiscord(clientID, clientSecret, redirectURL string) Provider {
	return &oauthAdapter{
		id: "discord", name: "Discord", profileURL: "https://discord.com/api/v10/users/@me",
		config: oauth2.Config{
			ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://discord.com/oauth2/authorize",
				TokenURL: "https://discord.com/api/oauth2/token",
			},
			Scopes: []string{"identify", "email"},
		},
		resolveProfile: func(ctx context.Context, client *http.Client) (Identity, error) {
			var profile struct {
				ID       string `json:"id"`
				Email    string `json:"email"`
				Verified bool   `json:"verified"`
			}
			if err := fetchProfile(ctx, client, "https://discord.com/api/v10/users/@me", &profile); err != nil {
				return Identity{}, err
			}
			if profile.ID == "" || profile.Email == "" {
				return Identity{}, fmt.Errorf("Discord profile has no email")
			}
			return Identity{Provider: "discord", Subject: profile.ID, Email: profile.Email, EmailVerified: profile.Verified}, nil
		},
	}
}
