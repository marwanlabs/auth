// Package httpapi wires the auth and store packages into JSON HTTP
// handlers, and registers routes on a *http.ServeMux.
package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"authserver/internal/auth"
	"authserver/internal/providers"
	"authserver/internal/socialauth"
	"authserver/internal/store"
)

type API struct {
	Auth       *auth.Service
	Users      UserRepository
	Sessions   SessionRepository
	Reset      ResetTokenRepository
	Providers  map[string]providers.Provider
	ProviderDB ProviderRepository
	Audit      store.AuditRepository
	Social     *socialauth.Service
	OAuth      store.OAuthTransactionRepository
}

func New(a *auth.Service, users UserRepository, sessions SessionRepository, reset ResetTokenRepository, providerDB ProviderRepository, social socialauth.Repository, audit store.AuditRepository) *API {
	oauth, _ := social.(store.OAuthTransactionRepository)
	return &API{Auth: a, Users: users, Sessions: sessions, Reset: reset, ProviderDB: providerDB, Audit: audit, Providers: make(map[string]providers.Provider), Social: socialauth.New(social), OAuth: oauth}
}

// Admin mutation rate limit: each sensitive administration action is capped
// per actor identity plus client address within one minute.
const (
	adminRateLimit  = 30
	adminRateWindow = time.Minute
)

// Register attaches all routes to mux.
func (api *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", api.handleHealth)
	const authRateLimit = 10
	const authRateWindow = time.Minute
	signupLimiter := auth.NewRateLimiter(authRateLimit, authRateWindow)
	loginLimiter := auth.NewRateLimiter(authRateLimit, authRateWindow)
	resetLimiter := auth.NewRateLimiter(authRateLimit, authRateWindow)
	adminRoleLimiter := auth.NewRateLimiter(adminRateLimit, adminRateWindow)
	adminStatusLimiter := auth.NewRateLimiter(adminRateLimit, adminRateWindow)
	adminDeleteLimiter := auth.NewRateLimiter(adminRateLimit, adminRateWindow)

	mux.HandleFunc("POST /api/signup", signupLimiter.Middleware(clientIPKey, api.handleSignup))
	mux.HandleFunc("POST /api/login", loginLimiter.Middleware(clientIPKey, api.handleLogin))
	mux.HandleFunc("POST /api/logout", api.Auth.RequireAuth(api.handleLogout))
	mux.HandleFunc("GET /api/me", api.Auth.RequireAuth(api.handleMe))
	mux.HandleFunc("POST /api/change-password", api.Auth.RequireAuth(api.handleChangePassword))
	mux.HandleFunc("GET /api/sessions", api.Auth.RequireAuth(api.handleListSessions))
	mux.HandleFunc("POST /api/sessions/revoke", api.Auth.RequireAuth(api.handleRevokeSession))
	mux.HandleFunc("POST /api/password-reset/request", resetLimiter.Middleware(clientIPKey, api.handleResetRequest))
	mux.HandleFunc("POST /api/password-reset/confirm", resetLimiter.Middleware(clientIPKey, api.handleResetConfirm))

	// Admin routes. Mutations are rate limited by actor identity and client
	// address, and every attempt (allowed, denied, or rate-limited) is
	// durably audited via adminMutation.
	mux.HandleFunc("GET /api/admin/users", api.Auth.RequireRole(store.RoleAdmin, api.handleListUsers))
	mux.HandleFunc("POST /api/admin/users/role", api.adminMutation("admin.change_user_role", adminRoleLimiter, api.handleChangeUserRole))
	mux.HandleFunc("POST /api/admin/users/status", api.adminMutation("admin.change_user_status", adminStatusLimiter, api.handleChangeUserStatus))
	mux.HandleFunc("POST /api/admin/users/delete", api.adminMutation("admin.delete_user", adminDeleteLimiter, api.handleDeleteUser))
}

func (api *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func clientIPKey(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}

// adminActorKey keys admin rate-limit slots by the authenticated actor's
// identity plus the client address, so one compromised session cannot change
// users or provider availability at unlimited rate.
func adminActorKey(r *http.Request) string {
	actor := ""
	if u := auth.UserFromContext(r.Context()); u != nil {
		actor = u.ID
	}
	return actor + "|" + clientIPKey(r)
}

// adminMutation guards a sensitive admin mutation. It requires the admin
// role, rate-limits excess requests by actor identity and client address
// before the handler runs, and records an audit event with the action outcome
// whether the request was performed, rejected, or rate-limited. Rejected
// requests never reach the handler, so they cannot change users or provider
// availability, and every attempt leaves a durable secret-free trail.
func (api *API) adminMutation(eventType string, limiter *auth.RateLimiter, next http.HandlerFunc) http.HandlerFunc {
	guarded := api.Auth.RequireRole(store.RoleAdmin, limiter.Middleware(adminActorKey, next))
	return func(w http.ResponseWriter, r *http.Request) {
		target := adminTarget(r)
		res := &statusRecorder{ResponseWriter: w}
		guarded(res, r)
		api.recordAdminEvent(r, eventType, target, adminOutcome(res.status))
	}
}

// statusRecorder forwards response writes to the real writer and remembers
// the first status code, which the admin audit wrapper uses to derive an
// event outcome.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func adminOutcome(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "success"
	case status == http.StatusTooManyRequests:
		return "rate_limited"
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return "forbidden"
	default:
		return "failure"
	}
}

// adminTarget extracts the affected user or provider id from a request body
// without consuming it, so the mutation handler can still process the
// request.
func adminTarget(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	var req struct {
		UserID   string `json:"user_id"`
		Provider string `json:"provider"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return ""
	}
	if req.UserID != "" {
		return req.UserID
	}
	return req.Provider
}

func (api *API) recordAdminEvent(r *http.Request, eventType, target, outcome string) {
	if api.Audit == nil {
		return
	}
	actorID, actorEmail := "", ""
	if u := api.Auth.AuthenticatedUser(r); u != nil {
		actorID, actorEmail = u.ID, u.Email
	}
	if err := api.Audit.CreateAuditEvent(&store.AuditEvent{
		ID:         mustID(),
		Type:       eventType,
		Outcome:    outcome,
		Timestamp:  time.Now(),
		ActorID:    actorID,
		ActorEmail: actorEmail,
		Target:     target,
		ClientIP:   clientIPKey(r),
		UserAgent:  r.UserAgent(),
	}); err != nil {
		log.Printf("record admin audit event: %v", err)
	}
}

// --- request/response helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON encode error: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func looksLikeEmail(email string) bool {
	at := strings.IndexByte(email, '@')
	return at > 0 && at < len(email)-1 && strings.Contains(email[at+1:], ".")
}

// --- handlers ---

type signupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (api *API) handleSignup(w http.ResponseWriter, r *http.Request) {
	auditOutcome := "failure"
	actorID, actorEmail := "", ""
	defer func() { api.recordAuthEvent(r, "signup", auditOutcome, actorID, actorEmail) }()

	var req signupRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	email := normalizeEmail(req.Email)
	if !looksLikeEmail(email) {
		writeError(w, http.StatusBadRequest, "enter a valid email address")
		return
	}
	if len(req.Password) < 10 {
		writeError(w, http.StatusBadRequest, "password must be at least 10 characters")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("hash password: %v", err)
		writeError(w, http.StatusInternalServerError, "could not create account")
		return
	}

	role := store.RoleUser
	if api.Users.CountUsers() == 0 {
		role = store.RoleAdmin // first user to sign up becomes admin
	}

	u := &store.User{
		ID:           mustID(),
		Email:        email,
		PasswordHash: hash,
		Role:         role,
		CreatedAt:    time.Now(),
	}
	if err := api.Users.CreateUser(u); err != nil {
		if err == store.ErrConflict {
			// Deliberately vague: don't reveal whether an email is
			// registered to an unauthenticated caller.
			writeError(w, http.StatusBadRequest, "could not create account with those details")
			return
		}
		log.Printf("create user: %v", err)
		writeError(w, http.StatusInternalServerError, "could not create account")
		return
	}
	actorID, actorEmail = u.ID, u.Email

	if err := api.Auth.SetSessionCookie(w, r, u.ID); err != nil {
		log.Printf("set session cookie: %v", err)
		writeError(w, http.StatusInternalServerError, "account created, but sign-in failed — try logging in")
		return
	}
	auditOutcome = "success"
	writeJSON(w, http.StatusCreated, publicUser(u))
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (api *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	auditOutcome := "failure"
	actorID, actorEmail := "", ""
	defer func() { api.recordAuthEvent(r, "login", auditOutcome, actorID, actorEmail) }()

	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	email := normalizeEmail(req.Email)

	u, err := api.Users.GetUserByEmail(email)
	if err != nil {
		// Same error for "no such user" and "wrong password" — don't leak
		// which emails are registered.
		writeError(w, http.StatusUnauthorized, "incorrect email or password")
		return
	}
	actorID, actorEmail = u.ID, u.Email
	ok, err := auth.VerifyPassword(req.Password, u.PasswordHash)
	if err != nil || !ok {
		writeError(w, http.StatusUnauthorized, "incorrect email or password")
		return
	}
	if err := api.Auth.SetSessionCookie(w, r, u.ID); err != nil {
		log.Printf("set session cookie: %v", err)
		writeError(w, http.StatusInternalServerError, "sign-in failed")
		return
	}
	auditOutcome = "success"
	writeJSON(w, http.StatusOK, publicUser(u))
}

func (api *API) recordAuthEvent(r *http.Request, eventType, outcome, actorID, actorEmail string) {
	if api.Audit == nil {
		return
	}
	event := &store.AuditEvent{
		ID:         mustID(),
		Type:       eventType,
		Outcome:    outcome,
		Timestamp:  time.Now(),
		ActorID:    actorID,
		ActorEmail: actorEmail,
		ClientIP:   clientIPKey(r),
		UserAgent:  r.UserAgent(),
	}
	if err := api.Audit.CreateAuditEvent(event); err != nil {
		log.Printf("record auth audit event: %v", err)
	}
}

func (api *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	api.Auth.ClearSessionCookie(w)
	// Note: this clears the cookie but the underlying session record is
	// deleted via handleRevokeSession/current if the client calls it, or
	// naturally expires. For an explicit server-side revoke on logout,
	// look up and delete the session before clearing the cookie.
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (api *API) handleMe(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	writeJSON(w, http.StatusOK, publicUser(u))
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (api *API) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	var req changePasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ok, err := auth.VerifyPassword(req.CurrentPassword, u.PasswordHash)
	if err != nil || !ok {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	if len(req.NewPassword) < 10 {
		writeError(w, http.StatusBadRequest, "password must be at least 10 characters")
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update password")
		return
	}
	u.PasswordHash = hash
	if err := api.Users.UpdateUser(u); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update password")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (api *API) handleListSessions(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	sessions, err := api.Sessions.ListSessionsForUser(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list sessions")
		return
	}
	type sessionView struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
		UserAgent string    `json:"user_agent"`
		IP        string    `json:"ip"`
	}
	out := make([]sessionView, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, sessionView{s.ID, s.CreatedAt, s.ExpiresAt, s.UserAgent, s.IP})
	}
	writeJSON(w, http.StatusOK, out)
}

type revokeRequest struct {
	SessionID string `json:"session_id"`
}

type userRoleRequest struct {
	UserID string     `json:"user_id"`
	Role   store.Role `json:"role"`
}

type userStatusRequest struct {
	UserID   string `json:"user_id"`
	Disabled bool   `json:"disabled"`
}

type deleteUserRequest struct {
	UserID string `json:"user_id"`
}

func (api *API) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	var req revokeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sess, err := api.Sessions.GetSession(req.SessionID)
	if err != nil || sess.UserID != u.ID {
		// Don't reveal whether the session ID exists at all.
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if err := api.Sessions.DeleteSession(req.SessionID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- Password reset (request emits a token; wiring it to a real email
// provider is left to you — see README) ---

type resetRequest struct {
	Email string `json:"email"`
}

func (api *API) handleResetRequest(w http.ResponseWriter, r *http.Request) {
	var req resetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	email := normalizeEmail(req.Email)
	// Always return 200 regardless of whether the email exists, so this
	// endpoint can't be used to enumerate registered users.
	u, err := api.Users.GetUserByEmail(email)
	if err == nil {
		token, terr := auth.NewToken(32)
		if terr == nil {
			rt := &store.ResetToken{
				TokenHash: auth.HashToken(token),
				UserID:    u.ID,
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}
			if serr := api.Reset.CreateResetToken(rt); serr == nil {
				// TODO: send `token` to the user's email address instead
				// of logging it. Logging it here makes the flow testable
				// without an email provider configured.
				log.Printf("password reset requested for %s — token: %s (expires in 1h)", email, token)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "if that email is registered, a reset link has been sent",
	})
}

type resetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (api *API) handleResetConfirm(w http.ResponseWriter, r *http.Request) {
	var req resetConfirmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.NewPassword) < 10 {
		writeError(w, http.StatusBadRequest, "password must be at least 10 characters")
		return
	}
	hash := auth.HashToken(req.Token)
	rt, err := api.Reset.GetResetToken(hash)
	if err != nil || time.Now().After(rt.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "reset link is invalid or has expired")
		return
	}
	u, err := api.Users.GetUserByID(rt.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "reset link is invalid or has expired")
		return
	}
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not reset password")
		return
	}
	u.PasswordHash = newHash
	if err := api.Users.UpdateUser(u); err != nil {
		writeError(w, http.StatusInternalServerError, "could not reset password")
		return
	}
	_ = api.Reset.DeleteResetToken(hash) // one-time use
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- Admin example ---

func (api *API) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users := api.Users.ListUsers()
	out := make([]publicUserView, 0, len(users))
	for _, u := range users {
		out = append(out, publicUser(u))
	}
	writeJSON(w, http.StatusOK, out)
}

func (api *API) handleChangeUserRole(w http.ResponseWriter, r *http.Request) {
	admin := auth.UserFromContext(r.Context())
	var req userRoleRequest
	if err := decodeJSON(r, &req); err != nil || (req.Role != store.RoleAdmin && req.Role != store.RoleUser) {
		writeError(w, http.StatusBadRequest, "invalid role request")
		return
	}
	if req.UserID == admin.ID {
		writeError(w, http.StatusBadRequest, "you cannot change your own role")
		return
	}
	u, err := api.Users.GetUserByID(req.UserID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if u.Role == store.RoleAdmin && req.Role == store.RoleUser && api.Users.CountAdmins() == 1 {
		writeError(w, http.StatusBadRequest, "cannot remove the last active administrator")
		return
	}
	u.Role = req.Role
	if err := api.Users.UpdateUser(u); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update user role")
		return
	}
	writeJSON(w, http.StatusOK, publicUser(u))
}

func (api *API) handleChangeUserStatus(w http.ResponseWriter, r *http.Request) {
	admin := auth.UserFromContext(r.Context())
	var req userStatusRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid status request")
		return
	}
	if req.UserID == admin.ID {
		writeError(w, http.StatusBadRequest, "you cannot disable your own account")
		return
	}
	u, err := api.Users.GetUserByID(req.UserID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if req.Disabled && u.Role == store.RoleAdmin && !u.Disabled && api.Users.CountAdmins() == 1 {
		writeError(w, http.StatusBadRequest, "cannot disable the last active administrator")
		return
	}
	u.Disabled = req.Disabled
	if err := api.Users.UpdateUser(u); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update user status")
		return
	}
	writeJSON(w, http.StatusOK, publicUser(u))
}

func (api *API) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	admin := auth.UserFromContext(r.Context())
	var req deleteUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid delete request")
		return
	}
	if req.UserID == admin.ID {
		writeError(w, http.StatusBadRequest, "you cannot delete your own account")
		return
	}
	if err := api.Users.DeleteUser(req.UserID); err != nil {
		if err == store.ErrNotFound {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not delete user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- shared view/id helpers ---

type publicUserView struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
}

func publicUser(u *store.User) publicUserView {
	return publicUserView{ID: u.ID, Email: u.Email, Role: string(u.Role), Disabled: u.Disabled, CreatedAt: u.CreatedAt}
}

func mustID() string {
	id, err := auth.NewToken(16)
	if err != nil {
		panic("auth: failed to generate id: " + err.Error())
	}
	return id
}
