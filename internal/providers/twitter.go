package providers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/oauth2"
)

type twitterProvider struct {
	config oauth2.Config
}

// NewTwitter creates a Twitter/X OAuth 2.0 provider using PKCE.
func NewTwitter(clientID, clientSecret, redirectURL string) Provider {
	return &twitterProvider{config: oauth2.Config{
		ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://twitter.com/i/oauth2/authorize",
			TokenURL: "https://api.x.com/2/oauth2/token",
		},
		Scopes: []string{"users.read", "users.email"},
	}}
}

func (p *twitterProvider) ID() string   { return "twitter" }
func (p *twitterProvider) Name() string { return "Twitter/X" }
func (p *twitterProvider) Configured() bool {
	return p.config.ClientID != "" && p.config.ClientSecret != "" && p.config.RedirectURL != ""
}
func (p *twitterProvider) Readiness() Readiness { return oauthReadiness(p.config) }
func (p *twitterProvider) AuthorizationURL(state string) string {
	digest := sha256.Sum256([]byte(state))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	return p.config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}
func (p *twitterProvider) Resolve(ctx context.Context, code string) (Identity, error) {
	return Identity{}, fmt.Errorf("Twitter/X token exchange requires PKCE state")
}
func (p *twitterProvider) ResolveWithState(ctx context.Context, code, state string) (Identity, error) {
	token, err := p.config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", state))
	if err != nil {
		return Identity{}, err
	}
	var response struct {
		Data struct {
			ID             string `json:"id"`
			ConfirmedEmail string `json:"confirmed_email"`
		} `json:"data"`
	}
	if err := fetchProfile(ctx, p.config.Client(ctx, token), "https://api.x.com/2/users/me?user.fields=id,confirmed_email", &response); err != nil {
		return Identity{}, err
	}
	if response.Data.ID == "" || response.Data.ConfirmedEmail == "" {
		return Identity{}, fmt.Errorf("Twitter/X profile has no confirmed email")
	}
	return Identity{Provider: "twitter", Subject: response.Data.ID, Email: response.Data.ConfirmedEmail, EmailVerified: true}, nil
}
