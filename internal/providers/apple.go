package providers

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

type appleProvider struct {
	config oauth2.Config
}

func NewApple(clientID, clientSecret, redirectURL string) Provider {
	return &appleProvider{config: oauth2.Config{
		ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
		Endpoint: oauth2.Endpoint{AuthURL: "https://appleid.apple.com/auth/authorize", TokenURL: "https://appleid.apple.com/auth/token"},
		Scopes:   []string{"name", "email"},
	}}
}

func (p *appleProvider) ID() string   { return "apple" }
func (p *appleProvider) Name() string { return "Apple" }
func (p *appleProvider) Configured() bool {
	return p.config.ClientID != "" && p.config.ClientSecret != "" && p.config.RedirectURL != ""
}
func (p *appleProvider) Readiness() Readiness { return oauthReadiness(p.config, p.ID()) }
func (p *appleProvider) AuthorizationURL(state string) string {
	return p.AuthorizationURLWithVerifier(state, state)
}
func (p *appleProvider) Resolve(ctx context.Context, code string) (Identity, error) {
	return p.ResolveWithVerifier(ctx, code, code)
}
func (p *appleProvider) AuthorizationURLWithVerifier(state, verifier string) string {
	return p.config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("response_mode", "form_post"),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}
func (p *appleProvider) ResolveWithVerifier(ctx context.Context, code, verifier string) (Identity, error) {
	token, err := p.config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return Identity{}, err
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		return Identity{}, fmt.Errorf("Apple token response has no identity token")
	}
	return verifyAppleIDToken(ctx, idToken, p.config.ClientID)
}

type appleClaims struct {
	Issuer        string      `json:"iss"`
	Subject       string      `json:"sub"`
	Audience      string      `json:"aud"`
	ExpiresAt     int64       `json:"exp"`
	Email         string      `json:"email"`
	EmailVerified interface{} `json:"email_verified"`
}

func verifyAppleIDToken(ctx context.Context, raw, clientID string) (Identity, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Identity{}, fmt.Errorf("invalid Apple identity token")
	}
	var header struct{ Alg, Kid string }
	if err := decodeJWTPart(parts[0], &header); err != nil || header.Alg != "RS256" || header.Kid == "" {
		return Identity{}, fmt.Errorf("invalid Apple identity token header")
	}
	var claims appleClaims
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return Identity{}, fmt.Errorf("invalid Apple identity token claims")
	}
	if claims.Issuer != "https://appleid.apple.com" || claims.Audience != clientID || claims.Subject == "" || claims.ExpiresAt <= time.Now().Unix() {
		return Identity{}, fmt.Errorf("invalid Apple identity token claims")
	}
	key, err := applePublicKey(ctx, header.Kid)
	if err != nil {
		return Identity{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return Identity{}, fmt.Errorf("invalid Apple identity token signature")
	}
	verified := claims.EmailVerified == true || claims.EmailVerified == "true"
	return Identity{Provider: "apple", Subject: claims.Subject, Email: claims.Email, EmailVerified: verified}, nil
}

func decodeJWTPart(part string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func applePublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	var response struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := fetchProfile(ctx, http.DefaultClient, "https://appleid.apple.com/auth/keys", &response); err != nil {
		return nil, err
	}
	for _, item := range response.Keys {
		if item.Kid != kid || item.Kty != "RSA" {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(item.N)
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(item.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	}
	return nil, fmt.Errorf("Apple signing key %q not found", kid)
}
