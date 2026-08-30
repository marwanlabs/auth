package providers

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// NewMicrosoft creates a Microsoft provider using the common tenant. This
// supports both personal Microsoft accounts and work/school accounts.
func NewMicrosoft(clientID, clientSecret, redirectURL string) Provider {
	return &oauthAdapter{
		id: "microsoft", name: "Microsoft", profileURL: "https://graph.microsoft.com/v1.0/me",
		config: oauth2.Config{
			ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
				TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			},
			Scopes: []string{"openid", "profile", "email", "User.Read"},
		},
		resolveProfile: func(ctx context.Context, client *http.Client) (Identity, error) {
			var profile struct {
				ID                string `json:"id"`
				Mail              string `json:"mail"`
				UserPrincipalName string `json:"userPrincipalName"`
			}
			if err := fetchProfile(ctx, client, "https://graph.microsoft.com/v1.0/me?$select=id,mail,userPrincipalName", &profile); err != nil {
				return Identity{}, err
			}
			if profile.ID == "" {
				return Identity{}, fmt.Errorf("Microsoft profile has no subject")
			}
			email := profile.Mail
			if email == "" {
				email = profile.UserPrincipalName
			}
			if email == "" {
				return Identity{}, fmt.Errorf("Microsoft profile has no email")
			}
			return Identity{Provider: "microsoft", Subject: profile.ID, Email: email, EmailVerified: true}, nil
		},
	}
}
