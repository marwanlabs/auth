# authserver

A minimal, self-hosted auth service: signup, login, sessions, roles, and
password reset — written in Go with **zero external dependencies** (stdlib
only), plus a plain HTML/CSS/JS frontend with no build step.

This is scoped for an internal tool, not a public multi-tenant SaaS. It
does not include organizations, billing, or fraud/bot detection — those
are what Clerk sells as a commercial product on top of the auth basics
covered here. Add them only if you actually need them.

## Run it

```
go run ./cmd/server
```

Then open http://localhost:8090 — it redirects to sign-up/sign-in.

The first account created automatically becomes an admin (role: "admin").
Everyone after that is a regular user.

## Development environment

This repository includes a Nix flake with the supported default Go toolchain,
`gopls`, and Go tools.
Enter it manually with:

```
nix develop
```

If you use direnv, allow the repository once:

```
direnv allow
```

After that, direnv automatically enters the Nix development environment when
you enter this directory. You can then run the server normally:

```
go run ./cmd/server
```

### Environment variables

| Variable               | Default            | Purpose                                                   |
|-------------------------|--------------------|-----------------------------------------------------------|
| `AUTH_ADDR`             | `:8090`            | Listen address                                            |
| `AUTH_DATA_FILE`        | `data/store.json`  | Where user/session data is persisted                      |
| `AUTH_SECURE_COOKIES`   | `false`            | Set to `true` once served over HTTPS (marks cookies Secure) |

## What's included

- Email + password signup/login (PBKDF2-HMAC-SHA256 hashing, 210k iterations)
- Session cookies (httpOnly, SameSite=Lax, 30-day expiry), hashed at rest
- Multi-device session tracking + per-device revocation ("sign out this device")
- CSRF protection (double-submit cookie) on all state-changing requests
- Role field (`user` / `admin`) with a `RequireRole` middleware
- Password change (requires current password)
- Password reset via emailed one-time link (single-use, 1-hour expiry)
- Rate limiting on auth endpoints (10 req/min/IP by default)
- No user enumeration: login, signup-conflict, and reset-request all return
  intentionally vague responses

## What you still need to wire up before real use

1. **Email delivery.** `handleResetRequest` currently logs the reset token
   instead of emailing it (see the `TODO` in
   `internal/httpapi/handlers.go`). Wire it to your email provider
   (SES, Postmark, SMTP, etc.) and send a link like
   `https://yourapp.com/reset-confirm.html?token=<token>`.
2. **HTTPS.** Run this behind a reverse proxy (Caddy, nginx, or your cloud
   load balancer) terminating TLS, and set `AUTH_SECURE_COOKIES=true`.
3. **Storage at scale.** The JSON-file store (`internal/store`) is fine for
   a small team/internal tool. If you outgrow it, the `Store` struct's
   methods are the only place to change — swap the JSON file for Postgres
   using `database/sql` and a driver of your choice, keeping the same
   method signatures.
4. **Backups.** Back up `data/store.json` like you would a database — it
   *is* your database.
5. **Social login / MFA**, if you want them: OAuth (Google/GitHub) and TOTP
   are both reasonable additions but aren't included here to keep this
   readable as a starting point rather than a framework.

## API reference

| Method | Path                          | Auth required | Description                       |
|--------|-------------------------------|----------------|------------------------------------|
| POST   | `/api/signup`                 | No             | Create account, starts a session   |
| POST   | `/api/login`                  | No             | Start a session                    |
| POST   | `/api/logout`                 | Yes            | Clear the current session cookie   |
| GET    | `/api/me`                     | Yes            | Current user info                  |
| POST   | `/api/change-password`        | Yes            | Requires current password          |
| GET    | `/api/sessions`                | Yes            | List your active sessions/devices  |
| POST   | `/api/sessions/revoke`         | Yes            | Revoke a specific session by ID    |
| POST   | `/api/password-reset/request`  | No             | Emits a reset token (see note above) |
| POST   | `/api/password-reset/confirm`  | No             | Consume token, set new password    |
| GET    | `/api/admin/users`             | Yes (admin)    | Example admin-only route           |

All state-changing (`POST`) requests require an `X-CSRF-Token` header
matching the `csrf_token` cookie — the included frontend JS
(`web/js/api.js`) handles this automatically.
