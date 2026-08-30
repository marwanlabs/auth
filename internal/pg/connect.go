package pg

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Connection pool limits for the shared runtime pool.
const (
	maxOpenConns    = 20
	maxIdleConns    = 10
	connMaxLifetime = 30 * time.Minute
	connMaxIdleTime = 5 * time.Minute
)

// Connect opens a connection pool for cfg and verifies it with a Ping so
// configuration or connectivity problems surface before the service accepts
// traffic. The pool stays open until the caller closes it; errors never
// expose the connection string or its password.
func Connect(ctx context.Context, cfg *Config) (*sql.DB, error) {
	connCfg, err := pgx.ParseConfig(cfg.dsn)
	if err != nil {
		return nil, redactError(cfg, err)
	}
	if connCfg.Config.ConnectTimeout == 0 {
		connCfg.Config.ConnectTimeout = 10 * time.Second
	}
	db := stdlib.OpenDB(*connCfg)
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetConnMaxIdleTime(connMaxIdleTime)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, redactError(cfg, fmt.Errorf("connecting to PostgreSQL: %w", err))
	}
	return db, nil
}
