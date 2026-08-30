# `@authserver/sdk-react`

React context and hooks for the [`@authserver/sdk`](../sdk) TypeScript client.
It provides a convenient way to load the current session and share it across a
React application. Authentication remains cookie-based; the package does not
store session tokens in `localStorage`.

## Installation

Install the SDK, this React integration, and React in your application:

```bash
npm install @authserver/sdk @authserver/sdk-react react
```

For local development inside this repository, use the demo in
[`../../demos/sdk-demo`](../../demos/sdk-demo) as a working example.

## Setup

Create one `AuthClient` and provide it near the root of the application:

```tsx
import { AuthClient } from "@authserver/sdk";
import { AuthProvider } from "@authserver/sdk-react";
import { App } from "./App";

const auth = new AuthClient({ baseUrl: "/api" });

export function Root() {
  return (
    <AuthProvider client={auth}>
      <App />
    </AuthProvider>
  );
}
```

Use `/api` when the React frontend and Go server share the same origin. For a
separate API host, provide its full API URL instead.

## Reading the session

`useAuth()` loads the current user when the provider mounts:

```tsx
import { useAuth } from "@authserver/sdk-react";

export function Account() {
  const { user, loading, logout } = useAuth();

  if (loading) return <p>Loading session...</p>;
  if (!user) return <p>Please sign in.</p>;

  return (
    <section>
      <p>Signed in as {user.email}</p>
      <button onClick={() => void logout()}>Sign out</button>
    </section>
  );
}
```

The context exposes:

- `user` — the current user or `null`
- `loading` — whether the initial session check is running
- `refresh()` — reloads the current user
- `logout()` — signs out and clears the local user state
- `client` — the underlying `AuthClient` for API operations

## Sign in and sign up

Call the client and refresh the provider state after a successful request:

```tsx
const { client, refresh } = useAuth();

await client.login(email, password);
await refresh();
```

The SDK sends cookies with requests and automatically includes the CSRF header
for state-changing operations.

## Protected and admin views

Use `useRequireAuth()` for a protected screen:

```tsx
const { user, loading, authenticated } = useRequireAuth();

if (loading) return <Loading />;
if (!authenticated) return <Login />;
return <Dashboard user={user!} />;
```

Use `useRequireRole("admin")` for an admin screen:

```tsx
const { loading, authorized } = useRequireRole("admin");

if (loading) return <Loading />;
if (!authorized) return <Forbidden />;
return <AdminDashboard />;
```

These hooks help control the UI, but the Go server remains responsible for
authorization. Never rely on hidden React buttons as a security boundary.

## Local development

When React runs on `localhost:5173` and authserver runs on `localhost:8090`,
configure a Vite proxy for `/api` and keep the SDK base URL as `/api`. This
keeps requests same-origin from the browser and preserves session and CSRF
cookie behavior.

See [`sdk-demo`](../../demos/sdk-demo) for the complete Vite configuration and a
runnable example.

## Important security notes

- Do not copy session cookies or passwords into `localStorage`.
- Serve production React and the API over HTTPS.
- Set `AUTH_SECURE_COOKIES=true` for the Go server in production.
- Use the backend API response as the source of truth for roles and access.
