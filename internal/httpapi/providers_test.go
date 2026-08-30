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
	if body := rec.Body.String(); !strings.Contains(body, "client_id") || !strings.Contains(body, "redirect_url") || strings.Contains(body, "secret-value") {
		t.Fatalf("unexpected validation response: %s", body)
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
	return New(&auth.Service{Store: s}, s, s, s, s, s), func() { os.Remove(file.Name()) }
}
