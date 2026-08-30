package pg

import (
	"strings"
	"testing"
)

func TestParseConfigAcceptsPostgresURL(t *testing.T) {
	cfg, err := ParseConfig("postgres://app:secret@localhost:5432/authserver?sslmode=disable")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.dsn == "" {
		t.Error("connection string not retained")
	}
	if cfg.password != "secret" {
		t.Errorf("password = %q, want %q", cfg.password, "secret")
	}
}

func TestParseConfigAcceptsKeywordValueForm(t *testing.T) {
	cfg, err := ParseConfig("host=localhost user=app password=kvsecret dbname=authserver")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.password != "kvsecret" {
		t.Errorf("password = %q, want %q", cfg.password, "kvsecret")
	}
}

func TestParseConfigRejectsEmpty(t *testing.T) {
	if _, err := ParseConfig("  "); err == nil {
		t.Fatal("expected error for empty connection string")
	}
}

func TestParseConfigRejectsUnknownScheme(t *testing.T) {
	_, err := ParseConfig("mysql://root:toor@localhost/authserver")
	if err == nil {
		t.Fatal("expected error for unknown scheme")
	}
	if strings.Contains(err.Error(), "toor") {
		t.Errorf("error exposes password: %q", err)
	}
}

func TestParseConfigMalformedDoesNotExposeSecrets(t *testing.T) {
	dsn := "postgres://app:bad%zzsecret@localhost/authserver"
	_, err := ParseConfig(dsn)
	if err == nil {
		t.Fatal("expected error for malformed connection string")
	}
	msg := err.Error()
	if strings.Contains(msg, "bad%zzsecret") {
		t.Errorf("error exposes password: %q", msg)
	}
	if strings.Contains(msg, dsn) {
		t.Errorf("error exposes full connection string: %q", msg)
	}
}

func TestConfigFromEnvNotSetIsNil(t *testing.T) {
	cfg, err := ConfigFromEnv(func(string) string { return "" })
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config when unset, got %v", cfg)
	}
}

func TestConfigFromEnvInvalid(t *testing.T) {
	_, err := ConfigFromEnv(func(key string) string {
		if key == DefaultEnvVar {
			return "postgres://app:envsecret@[broken"
		}
		return ""
	})
	if err == nil {
		t.Fatal("expected error for invalid environment configuration")
	}
	if strings.Contains(err.Error(), "envsecret") {
		t.Errorf("error exposes password: %q", err)
	}
}

func TestRedactErrorRemovesSecrets(t *testing.T) {
	cfg, err := ParseConfig("postgres://app:pwsecret@localhost/authserver")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	err = redactError(cfg, &synthetic{a: cfg.dsn, b: cfg.password})
	msg := err.Error()
	if strings.Contains(msg, cfg.dsn) {
		t.Errorf("error retains connection string: %q", msg)
	}
	if strings.Contains(msg, "pwsecret") {
		t.Errorf("error retains password: %q", msg)
	}
	if !strings.Contains(msg, "boom") || !strings.Contains(msg, "[redacted]") {
		t.Errorf("expected scrubbed wrapper around %q, got %q", "boom", msg)
	}
}

type synthetic struct{ a, b string }

func (s *synthetic) Error() string { return "boom " + s.a + " pw=" + s.b }
