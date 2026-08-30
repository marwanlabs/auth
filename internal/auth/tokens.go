package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// NewToken returns a URL-safe, base64-encoded random token with n bytes
// of entropy. Used for session tokens, CSRF tokens, password-reset tokens,
// and email-verification tokens.
func NewToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns a hex SHA-256 digest of a token. Session and reset
// tokens are stored hashed, the same way passwords are, so that a leak of
// the store's contents alone (e.g. a stolen backup file) doesn't hand out
// live sessions.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
