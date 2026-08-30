# Authserver SDK Demo

A small Vite + React application that demonstrates how to use the
`@authserver/sdk` package with the authserver Go API.

## Start the Go API

From the repository root:

```bash
go run ./cmd/server
```

The API runs at `http://localhost:8090` by default.

## Start the demo

In a second terminal:

```bash
cd demos/sdk-demo
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

The Vite development server proxies `/api` requests to
`http://localhost:8090`. This allows the browser to use the authserver session
and CSRF cookies normally.

## What it demonstrates

- Sign up
- Sign in and sign out
- Load the current user with `auth.me()`
- Refresh the profile
- Load users when signed in as an administrator
- Typed SDK errors
- Cookie-based sessions and CSRF-protected requests

The first account created by a fresh authserver data store becomes an admin,
so it can use the admin user-listing demo.

## Build for production

```bash
npm run build
npm run preview
```

For production, serve the built React files from your preferred web server and
configure `/api` to point to the authserver API. The production frontend and
API should normally be served from the same domain.
