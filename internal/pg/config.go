// Package pg provides the PostgreSQL runtime foundation for the auth
// service: it validates connection configuration, opens a hardened
// connection pool, and applies versioned schema migrations before the
// service accepts traffic. It deliberately owns no store logic; the
// PostgreSQL store implementation lands as a separate change.
//
// Connection configuration comes from server-owned environment/settings
// (AUTH_DATABASE_URL), never from committed files. Errors produced by this
// package never include the connection string, its password, or any other
// credential material.
package pg

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// DefaultEnvVar is the environment variable the server reads its PostgreSQL
// connection configuration from.
const DefaultEnvVar = "AUTH_DATABASE_URL"

// Config is a validated PostgreSQL connection configuration. It owns the
// connection string and never exposes it (or its password) in errors or
// string output.
type Config struct {
	dsn      string
	password string
}

// ConfigFromEnv builds a Config from a getenv-style lookup. It returns
// (nil, nil) when the variable is unset or empty; callers decide whether
// PostgreSQL is optional or required for their mode.
func ConfigFromEnv(getenv func(string) string) (*Config, error) {
	dsn := strings.TrimSpace(getenv(DefaultEnvVar))
	if dsn == "" {
		return nil, nil
	}
	return ParseConfig(dsn)
}

// ParseConfig validates a PostgreSQL connection string and returns the Config
// used to open connections. Both libpq keyword/value and URL forms are
// accepted. On any error the message is scrubbed so it never contains the
// full connection string or the embedded password.
func ParseConfig(dsn string) (*Config, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, errors.New("PostgreSQL connection string must not be empty")
	}
	connCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid PostgreSQL connection string: %s", scrub(dsn, "", err.Error()))
	}
	return &Config{dsn: dsn, password: connCfg.Config.Password}, nil
}
