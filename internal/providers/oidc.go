package providers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/oauth2"
)

type oidcProvider struct {
	issuer, clientID, clientSecret, redirectURL string
	mu                                          sync.RWMutex
	config                                      oauth2.Config
	userinfoURL                                 string
}

// NewOIDC creates a provider from an OpenID Connect issuer. Discovery is
// performed lazily so startup does not depend on the identity server being up.
func NewOIDC(issuer, clientID, clientSecret, redirectURL string) Provider {
	return &oidcProvider{issuer: strings.TrimRight(issuer, "/"), clientID: clientID, clientSecret: clientSecret, redirectURL: redirectURL}
}

func (p *oidcProvider) ID() string   { return "oidc" }
func (p *oidcProvider) Name() string { return "OpenID Connect" }
func (p *oidcProvider) Configured() bool {
	return p.issuer != "" && p.clientID != "" && p.clientSecret != "" && p.redirectURL != ""
}
func (p *oidcProvider) AuthorizationURL(state string) string {
	if err := p.discover(context.Background()); err != nil {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOnline)
}
func (p *oidcProvider) Resolve(ctx context.Context, code string) (Identity, error) {
	if err := p.discover(ctx); err != nil {
		return Identity{}, err
	}
	p.mu.RLock()
	config, userinfoURL := p.config, p.userinfoURL
	p.mu.RUnlock()
	token, err := config.Exchange(ctx, code)
	if err != nil {
		return Identity{}, err
	}
	var claims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := fetchProfile(ctx, config.Client(ctx, token), userinfoURL, &claims); err != nil {
		return Identity{}, err
	}
	if claims.Subject == "" || claims.Email == "" {
		return Identity{}, fmt.Errorf("OIDC userinfo has no email")
	}
	return Identity{Provider: "oidc", Subject: claims.Subject, Email: claims.Email, EmailVerified: claims.EmailVerified}, nil
}

func (p *oidcProvider) discover(ctx context.Context) error {
	p.mu.RLock()
	ready := p.config.Endpoint.AuthURL != "" && p.config.Endpoint.TokenURL != "" && p.userinfoURL != ""
	p.mu.RUnlock()
	if ready {
		return nil
	}
	if !p.Configured() {
		return fmt.Errorf("OIDC credentials are not configured")
	}
	var metadata struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
	}
	if err := fetchProfile(ctx, http.DefaultClient, p.issuer+"/.well-known/openid-configuration", &metadata); err != nil {
		return err
	}
	if metadata.AuthorizationEndpoint == "" || metadata.TokenEndpoint == "" || metadata.UserinfoEndpoint == "" {
		return fmt.Errorf("OIDC discovery metadata is incomplete")
	}
	p.mu.Lock()
	p.config = oauth2.Config{
		ClientID: p.clientID, ClientSecret: p.clientSecret, RedirectURL: p.redirectURL,
		Endpoint: oauth2.Endpoint{AuthURL: metadata.AuthorizationEndpoint, TokenURL: metadata.TokenEndpoint},
		Scopes:   []string{"openid", "profile", "email"},
	}
	p.userinfoURL = metadata.UserinfoEndpoint
	p.mu.Unlock()
	return nil
}
