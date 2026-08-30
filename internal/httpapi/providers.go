package httpapi

import (
	"authserver/internal/store"
	"net/http"
)

type providerView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Configured bool   `json:"configured"`
	Enabled    bool   `json:"enabled"`
}

var supportedProviders = []struct{ ID, Name string }{
	{"google", "Google"}, {"facebook", "Facebook"}, {"github", "GitHub"}, {"microsoft", "Microsoft"},
	{"apple", "Apple"}, {"gitlab", "GitLab"}, {"discord", "Discord"}, {"linkedin", "LinkedIn"},
	{"twitter", "Twitter/X"}, {"oidc", "OpenID Connect"},
}

func (api *API) RegisterProviderRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/auth/providers", api.handleListProviders)
	mux.HandleFunc("GET /api/admin/providers", api.Auth.RequireRole(store.RoleAdmin, api.handleListProviders))
	mux.HandleFunc("POST /api/admin/providers", api.Auth.RequireRole(store.RoleAdmin, api.handleSetProvider))
}

func (api *API) handleListProviders(w http.ResponseWriter, r *http.Request) {
	admin := r.URL.Path == "/api/admin/providers"
	settings := api.ProviderDB.ListProviderSettings()
	out := make([]providerView, 0, len(supportedProviders))
	for _, item := range supportedProviders {
		configured := api.providerConfigured(item.ID)
		enabled, explicit := settings[item.ID]
		if !explicit {
			enabled = configured && (item.ID == "google" || item.ID == "facebook")
		}
		if admin || enabled {
			out = append(out, providerView{ID: item.ID, Name: item.Name, Configured: configured, Enabled: enabled && configured})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type providerUpdateRequest struct {
	Provider string `json:"provider"`
	Enabled  bool   `json:"enabled"`
}

func (api *API) handleSetProvider(w http.ResponseWriter, r *http.Request) {
	var req providerUpdateRequest
	if err := decodeJSON(r, &req); err != nil || !isSupportedProvider(req.Provider) {
		writeError(w, http.StatusBadRequest, "invalid provider")
		return
	}
	if req.Enabled && !api.providerConfigured(req.Provider) {
		writeError(w, http.StatusBadRequest, "provider credentials are not configured")
		return
	}
	if err := api.ProviderDB.SetProviderEnabled(req.Provider, req.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update provider")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": req.Enabled})
}

func isSupportedProvider(id string) bool {
	for _, p := range supportedProviders {
		if p.ID == id {
			return true
		}
	}
	return false
}

func (api *API) providerConfigured(id string) bool {
	provider, ok := api.Providers[id]
	return ok && provider.Configured()
}

func (api *API) providerEnabled(id string) bool {
	if !api.providerConfigured(id) {
		return false
	}
	enabled, explicit := api.ProviderDB.ProviderSetting(id)
	if explicit {
		return enabled
	}
	return id == "google" || id == "facebook"
}
