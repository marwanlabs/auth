package httpapi

import (
	"authserver/internal/auth"
	"authserver/internal/providers"
	"authserver/internal/store"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestAdminProviderListIncludesSafeReadinessDiagnostics(t *testing.T) {
	api, cleanup := testProviderAPI(t)
	defer cleanup()
	api.Providers["github"] = providers.NewGitHub("", "secret-value", "")

	req := httptest.NewRequest(http.MethodGet, "/api/admin/providers", nil)
	rec := httptest.NewRecorder()
	api.handleListProviders(rec, req)

	var got []providerView
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	var github providerView
	for _, item := range got {
		if item.ID == "github" {
			github = item
		}
	}
	if github.Ready || github.Configured || github.Enabled {
		t.Fatalf("github readiness = %#v", github)
	}
	if want := []string{"client_id", "redirect_url"}; !strings.EqualFold(strings.Join(github.MissingRequirements, ","), strings.Join(want, ",")) {
		t.Fatalf("missing requirements = %#v, want %#v", github.MissingRequirements, want)
	}
	if strings.Contains(rec.Body.String(), "secret-value") {
		t.Fatal("response exposed a provider secret")
	}
	if len(github.SetupGuidance) == 0 || !strings.Contains(strings.Join(github.SetupGuidance, " "), "AUTH_GITHUB") {
		t.Fatalf("missing provider-specific setup guidance: %#v", github.SetupGuidance)
	}
}

func TestEnableIncompleteProviderReturnsActionableSafeError(t *testing.T) {
	api, cleanup := testProviderAPI(t)
	defer cleanup()
	api.Providers["github"] = providers.NewGitHub("", "secret-value", "")

	req := httptest.NewRequest(http.MethodPost, "/api/admin/providers", strings.NewReader(`{"provider":"github","enabled":true}`))
	rec := httptest.NewRecorder()
	api.handleSetProvider(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "client_id") || !strings.Contains(body, "redirect_url") || strings.Contains(body, "secret-value") {
		t.Fatalf("unexpected validation response: %s", body)
	}
	if !strings.Contains(body, `"code":"unavailable_configuration"`) {
		t.Fatalf("missing structured configuration error: %s", body)
	}
}

func TestProviderMutationUsesStructuredRequestAndDisableResponses(t *testing.T) {
	api, cleanup := testProviderAPI(t)
	defer cleanup()
	api.Providers["github"] = providers.NewGitHub("client", "secret", "http://localhost/callback")

	invalid := httptest.NewRequest(http.MethodPost, "/api/admin/providers", strings.NewReader(`{"provider":"unknown","enabled":true}`))
	invalidRec := httptest.NewRecorder()
	api.handleSetProvider(invalidRec, invalid)
	if invalidRec.Code != http.StatusBadRequest || !strings.Contains(invalidRec.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("invalid provider response = %d %s", invalidRec.Code, invalidRec.Body.String())
	}

	disable := httptest.NewRequest(http.MethodPost, "/api/admin/providers", strings.NewReader(`{"provider":"github","enabled":false}`))
	disableRec := httptest.NewRecorder()
	api.handleSetProvider(disableRec, disable)
	if disableRec.Code != http.StatusOK || !strings.Contains(disableRec.Body.String(), `"enabled":false`) {
		t.Fatalf("disable response = %d %s", disableRec.Code, disableRec.Body.String())
	}
}

func testProviderAPI(t *testing.T) (*API, func()) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "store-*.json")
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	s, err := store.Open(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return New(&auth.Service{Store: s}, s, s, s, s, s, s, s), func() { os.Remove(file.Name()) }
}
