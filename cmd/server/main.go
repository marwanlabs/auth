// Command server runs the auth service: a JSON API plus the static
// frontend, on a single port.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"authserver/internal/auth"
	"authserver/internal/httpapi"
	"authserver/internal/providers"
	"authserver/internal/store"
)

func main() {
	dataPath := getenv("AUTH_DATA_FILE", "data/store.json")
	addr := getenv("AUTH_ADDR", ":8090")
	secureCookies := getenv("AUTH_SECURE_COOKIES", "false") == "true"
	googleClientID := os.Getenv("AUTH_GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("AUTH_GOOGLE_CLIENT_SECRET")
	googleRedirectURL := getenv("AUTH_GOOGLE_REDIRECT_URL", "http://localhost:8090/api/auth/google/callback")

	if err := os.MkdirAll("data", 0700); err != nil {
		log.Fatalf("creating data dir: %v", err)
	}

	s, err := store.Open(dataPath)
	if err != nil {
		log.Fatalf("opening store: %v", err)
	}

	// Periodically clean up expired sessions and reset tokens.
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := s.DeleteExpiredSessions(); err != nil {
				log.Printf("cleanup: %v", err)
			}
		}
	}()

	authSvc := &auth.Service{Store: s, Secure: secureCookies}
	api := httpapi.New(authSvc, s)
	facebookClientID := os.Getenv("AUTH_FACEBOOK_CLIENT_ID")
	facebookClientSecret := os.Getenv("AUTH_FACEBOOK_CLIENT_SECRET")
	facebookRedirectURL := getenv("AUTH_FACEBOOK_REDIRECT_URL", "http://localhost:8090/api/auth/facebook/callback")
	githubClientID := os.Getenv("AUTH_GITHUB_CLIENT_ID")
	githubClientSecret := os.Getenv("AUTH_GITHUB_CLIENT_SECRET")
	githubRedirectURL := getenv("AUTH_GITHUB_REDIRECT_URL", "http://localhost:8090/api/auth/github/callback")
	microsoftClientID := os.Getenv("AUTH_MICROSOFT_CLIENT_ID")
	microsoftClientSecret := os.Getenv("AUTH_MICROSOFT_CLIENT_SECRET")
	microsoftRedirectURL := getenv("AUTH_MICROSOFT_REDIRECT_URL", "http://localhost:8090/api/auth/microsoft/callback")
	appleClientID := os.Getenv("AUTH_APPLE_CLIENT_ID")
	appleClientSecret := os.Getenv("AUTH_APPLE_CLIENT_SECRET")
	appleRedirectURL := getenv("AUTH_APPLE_REDIRECT_URL", "http://localhost:8090/api/auth/apple/callback")
	api.Providers["google"] = providers.NewGoogle(googleClientID, googleClientSecret, googleRedirectURL)
	api.Providers["facebook"] = providers.NewFacebook(facebookClientID, facebookClientSecret, facebookRedirectURL)
	api.Providers["github"] = providers.NewGitHub(githubClientID, githubClientSecret, githubRedirectURL)
	api.Providers["microsoft"] = providers.NewMicrosoft(microsoftClientID, microsoftClientSecret, microsoftRedirectURL)
	api.Providers["apple"] = providers.NewApple(appleClientID, appleClientSecret, appleRedirectURL)

	mux := http.NewServeMux()
	api.Register(mux)
	api.RegisterSocialRoutes(mux)
	api.RegisterProviderRoutes(mux)

	// Serve the static frontend from ./web at the root.
	fs := http.FileServer(http.Dir("web"))
	mux.Handle("/", fs)

	if !secureCookies {
		log.Printf("WARNING: AUTH_SECURE_COOKIES is not \"true\" — cookies will be sent over plain HTTP. Set AUTH_SECURE_COOKIES=true once you're behind HTTPS.")
	}
	log.Printf("listening on %s (data file: %s)", addr, dataPath)
	log.Fatal(http.ListenAndServe(addr, logRequests(mux)))
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
