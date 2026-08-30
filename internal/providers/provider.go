package providers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

type Identity struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
}

// Readiness contains only configuration facts that are safe to show to an
// administrator. Missing names identify inputs, never their values.
type Readiness struct {
	Ready   bool
	Missing []string
}

type Provider interface {
	ID() string
	Name() string
	Configured() bool
	AuthorizationURL(state string) string
	Resolve(ctx context.Context, code string) (Identity, error)
}

// ReadinessProvider adds safe configuration diagnostics to a Provider.
type ReadinessProvider interface {
	Provider
	Readiness() Readiness
}

func oauthReadiness(config oauth2.Config) Readiness {
	missing := make([]string, 0, 3)
	if config.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if config.ClientSecret == "" {
		missing = append(missing, "client_secret")
	}
	if config.RedirectURL == "" {
		missing = append(missing, "redirect_url")
	}
	return Readiness{Ready: len(missing) == 0, Missing: missing}
}

// StatefulProvider is implemented by providers whose token exchange also
// needs the authorization request state, such as OAuth providers using PKCE.
type StatefulProvider interface {
	Provider
	ResolveWithState(ctx context.Context, code, state string) (Identity, error)
}

// PKCEProvider keeps the verifier out of the browser-visible OAuth state.
type PKCEProvider interface {
	Provider
	AuthorizationURLWithVerifier(state, verifier string) string
	ResolveWithVerifier(ctx context.Context, code, verifier string) (Identity, error)
}

type oauthAdapter struct {
	config         oauth2.Config
	id             string
	name           string
	profileURL     string
	resolveProfile func(context.Context, *http.Client) (Identity, error)
}

func (p *oauthAdapter) ID() string   { return p.id }
func (p *oauthAdapter) Name() string { return p.name }
func (p *oauthAdapter) Configured() bool {
	return p.config.ClientID != "" && p.config.ClientSecret != "" && p.config.RedirectURL != "" && p.config.Endpoint.AuthURL != "" && p.profileURL != ""
}
func (p *oauthAdapter) Readiness() Readiness { return oauthReadiness(p.config) }
func (p *oauthAdapter) AuthorizationURL(state string) string {
	return p.AuthorizationURLWithVerifier(state, state)
}
func (p *oauthAdapter) Resolve(ctx context.Context, code string) (Identity, error) {
	return p.ResolveWithVerifier(ctx, code, code)
}
func (p *oauthAdapter) AuthorizationURLWithVerifier(state, verifier string) string {
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}
func (p *oauthAdapter) ResolveWithVerifier(ctx context.Context, code, verifier string) (Identity, error) {
	token, err := p.config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return Identity{}, err
	}
	return p.resolveProfile(ctx, p.config.Client(ctx, token))
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func fetchProfile(ctx context.Context, client *http.Client, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("profile endpoint returned %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}
