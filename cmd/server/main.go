// Command server runs the auth service: a JSON API plus the static
// frontend, on a single port.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"authserver/internal/auth"
	"authserver/internal/httpapi"
	"authserver/internal/pg"
	"authserver/internal/providers"
	"authserver/internal/store"
)

func main() {
	dataPath := getenv("AUTH_DATA_FILE", "data/store.json")
	addr := getenv("AUTH_ADDR", ":8090")
	secureCookies := getenv("AUTH_SECURE_COOKIES", "false") == "true"

	// PostgreSQL runtime foundation (optional): when AUTH_DATABASE_URL is
	// set, validate the configuration, connect, and apply schema migrations
	// before accepting any traffic. Any failure here is fatal and reported
	// without credentials. The JSON-file store stays in use until the store
	// cutover (issue #19).
	dbCfg, dbCfgErr := pg.ConfigFromEnv(os.Getenv)
	if dbCfgErr != nil {
		log.Fatalf("postgres configuration: %v", dbCfgErr)
	}
	if dbCfg != nil {
		connectCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		pgDB, connectErr := pg.Connect(connectCtx, dbCfg)
		cancel()
		if connectErr != nil {
			log.Fatalf("postgres connection: %v", connectErr)
		}
		defer pgDB.Close()
		migrateCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		version, migrateErr := pg.Migrate(migrateCtx, pgDB)
		cancel()
		if migrateErr != nil {
			log.Fatalf("postgres migration: %v", migrateErr)
		}
		log.Printf("postgres ready: schema version %d", version)
	}

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
	api := httpapi.New(authSvc, s, s, s, s, s, s)
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
	gitlabClientID := os.Getenv("AUTH_GITLAB_CLIENT_ID")
	gitlabClientSecret := os.Getenv("AUTH_GITLAB_CLIENT_SECRET")
	gitlabRedirectURL := getenv("AUTH_GITLAB_REDIRECT_URL", "http://localhost:8090/api/auth/gitlab/callback")
	discordClientID := os.Getenv("AUTH_DISCORD_CLIENT_ID")
	discordClientSecret := os.Getenv("AUTH_DISCORD_CLIENT_SECRET")
	discordRedirectURL := getenv("AUTH_DISCORD_REDIRECT_URL", "http://localhost:8090/api/auth/discord/callback")
	linkedinClientID := os.Getenv("AUTH_LINKEDIN_CLIENT_ID")
	linkedinClientSecret := os.Getenv("AUTH_LINKEDIN_CLIENT_SECRET")
	linkedinRedirectURL := getenv("AUTH_LINKEDIN_REDIRECT_URL", "http://localhost:8090/api/auth/linkedin/callback")
	twitterClientID := os.Getenv("AUTH_TWITTER_CLIENT_ID")
	twitterClientSecret := os.Getenv("AUTH_TWITTER_CLIENT_SECRET")
	twitterRedirectURL := getenv("AUTH_TWITTER_REDIRECT_URL", "http://localhost:8090/api/auth/twitter/callback")
	oidcIssuer := os.Getenv("AUTH_OIDC_ISSUER")
	oidcClientID := os.Getenv("AUTH_OIDC_CLIENT_ID")
	oidcClientSecret := os.Getenv("AUTH_OIDC_CLIENT_SECRET")
	oidcRedirectURL := getenv("AUTH_OIDC_REDIRECT_URL", "http://localhost:8090/api/auth/oidc/callback")
	api.Providers["google"] = providers.NewGoogle(googleClientID, googleClientSecret, googleRedirectURL)
	api.Providers["facebook"] = providers.NewFacebook(facebookClientID, facebookClientSecret, facebookRedirectURL)
	api.Providers["github"] = providers.NewGitHub(githubClientID, githubClientSecret, githubRedirectURL)
	api.Providers["microsoft"] = providers.NewMicrosoft(microsoftClientID, microsoftClientSecret, microsoftRedirectURL)
	api.Providers["apple"] = providers.NewApple(appleClientID, appleClientSecret, appleRedirectURL)
	api.Providers["gitlab"] = providers.NewGitLab(gitlabClientID, gitlabClientSecret, gitlabRedirectURL)
	api.Providers["discord"] = providers.NewDiscord(discordClientID, discordClientSecret, discordRedirectURL)
	api.Providers["linkedin"] = providers.NewLinkedIn(linkedinClientID, linkedinClientSecret, linkedinRedirectURL)
	api.Providers["twitter"] = providers.NewTwitter(twitterClientID, twitterClientSecret, twitterRedirectURL)
	api.Providers["oidc"] = providers.NewOIDC(oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL)

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
