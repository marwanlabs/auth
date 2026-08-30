# Authserver Next.js SDK Demo

This demo uses the App Router integration in `@authserver/sdk-next` together
with the browser client from `@authserver/sdk`.

## Start the Go API

From the repository root:

```bash
go run ./cmd/server
```

The Go API must be available at `http://127.0.0.1:8090`.

## Start the Next.js demo

In a second terminal:

```bash
cd demos/sdk-next-demo
npm install
npm run dev
```

Open http://localhost:3000.

## What it demonstrates

- Server-side session loading with `getServerUser()`
- Browser login with `@authserver/sdk`
- Server-side admin user listing
- Browser logout followed by an SSR refresh
- Next.js rewrite proxying `/api` to the Go server

The first account created in a fresh authserver data store becomes an admin
and can see the server-loaded user list.
