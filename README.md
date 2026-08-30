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
`gopls`, Go tools, and Caddy.
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

## HTTPS and self-hosting

The server is designed to run behind [Caddy](https://caddyserver.com/), which
handles HTTPS while the Go service listens privately on port 8090. Example
configurations are in `deploy/Caddyfile` (production) and
`deploy/Caddyfile.local` (local HTTPS).

For normal local development, run:

```
go run ./cmd/server
```

Then open http://localhost:8090. For local HTTPS, start the server with
`AUTH_SECURE_COOKIES=true` and run Caddy with the local configuration:

```
AUTH_SECURE_COOKIES=true go run ./cmd/server
caddy run --config deploy/Caddyfile.local
```

Then open https://localhost:8443. Caddy's `tls internal` certificate may need
to be trusted in your browser or operating system once.

For a production server, replace `your-domain.example` in
`deploy/Caddyfile`, point the domain at the server, and make ports 80 and 443
reachable. Run the Go service with:

```
AUTH_ADDR=:8090 AUTH_SECURE_COOKIES=true go run ./cmd/server
caddy run --config deploy/Caddyfile
```

Do not expose port 8090 publicly; only Caddy should accept internet traffic.
Caddy will obtain and renew the public certificate when the domain is ready.
Back up the configured `AUTH_DATA_FILE` regularly.

The `/healthz` endpoint returns `{"status":"ok"}` and can be used by a
service manager or monitoring system.

## TypeScript SDK

The `packages/sdk/` directory contains the browser-friendly `@authserver/sdk`
package, `packages/sdk-react/` contains the optional React provider and hooks,
and `packages/sdk-next/` contains the Next.js App Router integration. From a
React application, install or link the relevant packages and create a client with
`baseUrl: "/api"` when the frontend is served through the same host.

The `demos/sdk-demo/` directory is a small Vite application showing the SDK in use.
With the Go server running on port 8090:

```
cd demos/sdk-demo
npm install
npm run dev
```

Open http://localhost:5173. The Vite proxy forwards `/api` requests to the Go
server, so browser cookies and CSRF protection work as they do in production.

The `demos/sdk-next-demo/` directory is a Next.js App Router example showing
SSR session checks and browser login. Run it with:

```
cd demos/sdk-next-demo
npm install
npm run dev
```

Then open http://localhost:3000.

### Authentication architecture

Social sign-in is split into provider adapters under `internal/providers/`, a
shared account-linking service under `internal/socialauth/`, and thin HTTP
handlers under `internal/httpapi/`. Adding a provider means implementing the
provider interface and registering the adapter; OAuth state, identity linking,
roles, disabled users, and sessions remain shared behavior.

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
- Admin user-management dashboard: search users, change roles, disable/enable accounts, and delete accounts
- Password change (requires current password)
- Password reset via emailed one-time link (single-use, 1-hour expiry)
- Optional Google OAuth sign-in with automatic linking to existing email accounts
- Optional Google, Facebook, and GitHub OAuth sign-in with administrator-controlled availability
- Optional Google and Facebook OAuth sign-in with administrator-controlled availability
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
5. **MFA**, if you need it: TOTP or passkeys are reasonable next additions.

### Google sign-in

Create a Web OAuth client in Google Cloud Console, add the redirect URI below,
then set these variables before starting the server:

```
AUTH_GOOGLE_CLIENT_ID=...
AUTH_GOOGLE_CLIENT_SECRET=...
AUTH_GOOGLE_REDIRECT_URL=http://localhost:8090/api/auth/google/callback
```

For HTTPS, use your public HTTPS callback URL and set
`AUTH_SECURE_COOKIES=true`. Google sign-in is then available on the sign-in
page. Existing accounts with the same verified email are linked automatically.
For the local Caddy setup, use
`https://localhost:8443/api/auth/google/callback` as the redirect URL and add
that exact URL to the Google OAuth client.

### Microsoft sign-in

Register an application in the Microsoft Entra admin center, add the callback
URL, create a client secret, and grant delegated `User.Read` permission. Use
the common tenant to support personal and work/school accounts:

```
AUTH_MICROSOFT_CLIENT_ID=...
AUTH_MICROSOFT_CLIENT_SECRET=...
AUTH_MICROSOFT_REDIRECT_URL=http://localhost:8090/api/auth/microsoft/callback
```

Then enable Microsoft from the admin dashboard under Sign-in providers. For
local HTTPS, use
`https://localhost:8443/api/auth/microsoft/callback` as the callback URL.

### Apple sign-in

Create a Sign in with Apple Services ID and private key in Apple Developer,
then generate the client-secret JWT required by Apple and provide it as
`AUTH_APPLE_CLIENT_SECRET`:

```
AUTH_APPLE_CLIENT_ID=...
AUTH_APPLE_CLIENT_SECRET=...
AUTH_APPLE_REDIRECT_URL=http://localhost:8090/api/auth/apple/callback
```

Apple sends its callback with `form_post`. The server accepts that callback,
validates the ID token signature using Apple's public keys, and uses Apple's
stable subject identifier for account linking. Enable Apple from the admin
dashboard after configuring the credentials.

### GitLab sign-in

Create an OAuth application in GitLab with the `read_user` and `email` scopes:

```
AUTH_GITLAB_CLIENT_ID=...
AUTH_GITLAB_CLIENT_SECRET=...
AUTH_GITLAB_REDIRECT_URL=http://localhost:8090/api/auth/gitlab/callback
```

This integration targets GitLab.com. Enable GitLab from the admin dashboard
after configuring the credentials.

### Discord sign-in

Create an application in the Discord Developer Portal and add an OAuth2
redirect URL. The integration requests only `identify` and `email`:

```
AUTH_DISCORD_CLIENT_ID=...
AUTH_DISCORD_CLIENT_SECRET=...
AUTH_DISCORD_REDIRECT_URL=http://localhost:8090/api/auth/discord/callback
```

Enable Discord from the admin dashboard after configuring the credentials.

### LinkedIn sign-in

Create a LinkedIn application with Sign In with LinkedIn using OpenID Connect
enabled, then add the callback URL:

```
AUTH_LINKEDIN_CLIENT_ID=...
AUTH_LINKEDIN_CLIENT_SECRET=...
AUTH_LINKEDIN_REDIRECT_URL=http://localhost:8090/api/auth/linkedin/callback
```

The integration requests `openid`, `profile`, and `email`. Enable LinkedIn
from the admin dashboard after configuring the credentials.

### Twitter/X sign-in

Create an OAuth 2.0 application in the X Developer Portal with `users.read`
and `users.email` access:

```
AUTH_TWITTER_CLIENT_ID=...
AUTH_TWITTER_CLIENT_SECRET=...
AUTH_TWITTER_REDIRECT_URL=http://localhost:8090/api/auth/twitter/callback
```

The integration requires X to return a confirmed email address. Enable
Twitter/X from the admin dashboard after configuring the credentials.

## API reference

| Method | Path                          | Auth required | Description                       |
|--------|-------------------------------|----------------|------------------------------------|
| POST   | `/api/signup`                 | No             | Create account, starts a session   |
| POST   | `/api/login`                  | No             | Start a session                    |
| GET    | `/api/auth/google`            | No             | Start Google sign-in (when configured) |
| GET    | `/api/auth/google/callback`   | No             | Complete Google sign-in            |
| GET    | `/api/auth/facebook`           | No             | Start Facebook sign-in             |
| GET    | `/api/auth/facebook/callback`  | No             | Complete Facebook sign-in           |
| GET    | `/api/auth/github`              | No             | Start GitHub sign-in                |
| GET    | `/api/auth/github/callback`     | No             | Complete GitHub sign-in             |
| GET    | `/api/auth/microsoft`           | No             | Start Microsoft sign-in             |
| GET    | `/api/auth/microsoft/callback`  | No             | Complete Microsoft sign-in          |
| GET    | `/api/auth/apple`               | No             | Start Apple sign-in                 |
| GET/POST | `/api/auth/apple/callback`    | No             | Complete Apple sign-in              |
| GET    | `/api/auth/gitlab`              | No             | Start GitLab sign-in                |
| GET    | `/api/auth/gitlab/callback`     | No             | Complete GitLab sign-in             |
| GET    | `/api/auth/discord`             | No             | Start Discord sign-in               |
| GET    | `/api/auth/discord/callback`    | No             | Complete Discord sign-in            |
| GET    | `/api/auth/linkedin`             | No             | Start LinkedIn sign-in              |
| GET    | `/api/auth/linkedin/callback`    | No             | Complete LinkedIn sign-in           |
| GET    | `/api/auth/twitter`              | No             | Start Twitter/X sign-in              |
| GET    | `/api/auth/twitter/callback`     | No             | Complete Twitter/X sign-in           |
| GET    | `/api/auth/providers`          | No             | List enabled social providers      |
| POST   | `/api/logout`                 | Yes            | Clear the current session cookie   |
| GET    | `/api/me`                     | Yes            | Current user info                  |
| POST   | `/api/change-password`        | Yes            | Requires current password          |
| GET    | `/api/sessions`                | Yes            | List your active sessions/devices  |
| POST   | `/api/sessions/revoke`         | Yes            | Revoke a specific session by ID    |
| POST   | `/api/password-reset/request`  | No             | Emits a reset token (see note above) |
| POST   | `/api/password-reset/confirm`  | No             | Consume token, set new password    |
| GET    | `/api/admin/users`             | Yes (admin)    | List all users                     |
| POST   | `/api/admin/users/role`        | Yes (admin)    | Change another user's role         |
| POST   | `/api/admin/users/status`      | Yes (admin)    | Disable or enable another user     |
| POST   | `/api/admin/users/delete`      | Yes (admin)    | Permanently delete another user   |
| GET    | `/api/admin/providers`         | Yes (admin)    | List social-provider settings     |
| POST   | `/api/admin/providers`         | Yes (admin)    | Enable or disable a provider      |

All state-changing (`POST`) requests require an `X-CSRF-Token` header
matching the `csrf_token` cookie — the included frontend JS
(`web/js/api.js`) handles this automatically.
