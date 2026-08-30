package pg

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestConnectFailureDoesNotExposeSecrets dials a dead port with a password in
// the connection string and asserts the resulting error never mentions it.
// Running offline is fine: the dial is refused immediately.
func TestConnectFailureDoesNotExposeSecrets(t *testing.T) {
	dsn := "postgres://app:supersecretpassword@127.0.0.1:65534/authserver"
	cfg, err := ParseConfig(dsn)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := Connect(ctx, cfg)
	if db != nil {
		db.Close()
	}
	if err == nil {
		t.Fatal("expected connection to fail against a closed port")
	}
	msg := err.Error()
	if strings.Contains(msg, "supersecretpassword") {
		t.Errorf("connection error exposes password: %q", msg)
	}
	if strings.Contains(msg, dsn) {
		t.Errorf("connection error exposes full connection string: %q", msg)
	}
}
