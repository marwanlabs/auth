package auth

import (
	"context"
	"net/http"
	"sync"
	"time"

	"authserver/internal/store"
)

const (
	SessionCookieName = "session"
	CSRFCookieName    = "csrf_token"
	CSRFHeaderName    = "X-CSRF-Token"
	SessionTTL        = 30 * 24 * time.Hour // 30 days
)

type ctxKey int

const userCtxKey ctxKey = 0

// UserFromContext returns the authenticated user for this request, or nil
// if the request is unauthenticated.
func UserFromContext(ctx context.Context) *store.User {
	u, _ := ctx.Value(userCtxKey).(*store.User)
	return u
}

// Service bundles the store with the middleware/handlers that operate on it.
type Service struct {
	Store *store.Store
	// Secure controls the Secure flag on cookies. Set true in production
	// (HTTPS). Left false only for local http:// development.
	Secure bool
}

// SetSessionCookie issues a new session for userID and writes both the
// session cookie (httpOnly) and a matching CSRF cookie (readable by JS).
func (s *Service) SetSessionCookie(w http.ResponseWriter, r *http.Request, userID string) error {
	token, err := NewToken(32)
	if err != nil {
		return err
	}
	sess := &store.Session{
		ID:        mustToken(16),
		UserID:    userID,
		TokenHash: HashToken(token),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(SessionTTL),
		UserAgent: r.UserAgent(),
		IP:        clientIP(r),
	}
	if err := s.Store.CreateSession(sess); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.ID + "." + token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
	})

	csrfToken, err := NewToken(24)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false, // JS needs to read this and echo it back in a header
		Secure:   s.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
	})
	return nil
}

func mustToken(n int) string {
	t, err := NewToken(n)
	if err != nil {
		// crypto/rand failing means the system is in serious trouble;
		// there's no safe fallback for a session ID.
		panic("auth: failed to generate random token: " + err.Error())
	}
	return t
}

// ClearSessionCookie logs the current device out.
func (s *Service) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: CSRFCookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: s.Secure, SameSite: http.SameSiteLaxMode,
	})
}

// RequireAuth validates the session cookie and attaches the user to the
// request context. It also enforces CSRF protection (double-submit cookie)
// on any state-changing method.
func (s *Service) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, sessID, ok := s.authenticate(r)
		if !ok {
			http.Error(w, `{"error":"not authenticated"}`, http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if !s.validCSRF(r) {
				http.Error(w, `{"error":"invalid csrf token"}`, http.StatusForbidden)
				return
			}
		}
		_ = sessID
		ctx := context.WithValue(r.Context(), userCtxKey, user)
		next(w, r.WithContext(ctx))
	}
}

// RequireRole wraps RequireAuth and additionally checks the user's role.
func (s *Service) RequireRole(role store.Role, next http.HandlerFunc) http.HandlerFunc {
	return s.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		u := UserFromContext(r.Context())
		if u == nil || u.Role != role {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// authenticate looks up the session referenced by the request's cookie.
// It does not enforce CSRF — callers decide when that's required.
func (s *Service) authenticate(r *http.Request) (*store.User, string, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, "", false
	}
	sessID, token, ok := splitCookie(cookie.Value)
	if !ok {
		return nil, "", false
	}
	sess, err := s.Store.GetSession(sessID)
	if err != nil {
		return nil, "", false
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, "", false
	}
	if HashToken(token) != sess.TokenHash {
		return nil, "", false
	}
	user, err := s.Store.GetUserByID(sess.UserID)
	if err != nil {
		return nil, "", false
	}
	return user, sess.ID, true
}

func splitCookie(v string) (id, token string, ok bool) {
	for i := 0; i < len(v); i++ {
		if v[i] == '.' {
			return v[:i], v[i+1:], true
		}
	}
	return "", "", false
}

func (s *Service) validCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(CSRFCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	header := r.Header.Get(CSRFHeaderName)
	return header != "" && header == cookie.Value
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}

// --- Simple in-memory rate limiter (fixed window per key, e.g. per IP) ---

type RateLimiter struct {
	mu       sync.Mutex
	window   time.Duration
	max      int
	counters map[string]*counter
}

type counter struct {
	count     int
	windowEnd time.Time
}

func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	return &RateLimiter{max: max, window: window, counters: make(map[string]*counter)}
}

// Allow reports whether another request from key is permitted right now,
// and increments the counter if so.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	c, ok := rl.counters[key]
	if !ok || now.After(c.windowEnd) {
		rl.counters[key] = &counter{count: 1, windowEnd: now.Add(rl.window)}
		return true
	}
	if c.count >= rl.max {
		return false
	}
	c.count++
	return true
}

// Middleware wraps a handler, rejecting requests over the limit with 429.
// keyFn extracts the rate-limit key (typically client IP) from the request.
func (rl *RateLimiter) Middleware(keyFn func(*http.Request) string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(keyFn(r)) {
			http.Error(w, `{"error":"too many requests, try again later"}`, http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}
