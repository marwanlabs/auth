package providers

import (
	"reflect"
	"testing"
)

func TestProviderReadinessReportsMissingRequirements(t *testing.T) {
	tests := []struct {
		name     string
		provider Provider
		missing  []string
	}{
		{"oauth", NewGitHub("", "secret-value", ""), []string{"client_id", "redirect_url"}},
		{"apple", NewApple("client", "", "callback"), []string{"client_secret"}},
		{"twitter", NewTwitter("client", "secret", "callback"), []string{}},
		{"oidc", NewOIDC("", "client", "secret", "callback"), []string{"issuer"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readiness := tt.provider.(ReadinessProvider).Readiness()
			if got := readiness.Missing; !reflect.DeepEqual(got, tt.missing) {
				t.Fatalf("missing requirements = %#v, want %#v", got, tt.missing)
			}
			if readiness.Ready != (len(tt.missing) == 0) {
				t.Fatalf("ready = %t, missing = %#v", readiness.Ready, readiness.Missing)
			}
		})
	}
}
