# `@authserver/sdk-next`

Next.js App Router integration for [`@authserver/sdk`](../sdk). It provides
server-side helpers that forward the current Next.js request cookies to the Go
authserver API without exposing session tokens to client code.

## Installation

```bash
npm install @authserver/sdk @authserver/sdk-next
```

The package requires Next.js 14 or newer and is intended for Server Components,
Route Handlers, and Server Actions.

## Configuration

Set the server-only API URL:

```env
AUTH_SERVER_URL=http://127.0.0.1:8090/api
```

In production, keep this pointed at the private Go API address. The browser
should access the Next.js application through the public HTTPS domain.

## Server Component example

```tsx
import { requireUser } from "@authserver/sdk-next/server";

export default async function DashboardPage() {
  const user = await requireUser({ loginPath: "/login" });

  return <h1>Welcome, {user.email}</h1>;
}
```

`requireUser()` redirects anonymous visitors to `/login`. Use
`getServerUser()` when a redirect is not appropriate:

```tsx
import { getServerUser } from "@authserver/sdk-next/server";

export default async function Header() {
  const user = await getServerUser();
  return user ? <p>{user.email}</p> : <a href="/login">Sign in</a>;
}
```

## Admin pages

```tsx
import { requireRole } from "@authserver/sdk-next/server";

export default async function AdminPage() {
  const admin = await requireRole("admin");
  const auth = await import("@authserver/sdk-next/server").then(
    ({ createServerAuthClient }) => createServerAuthClient(),
  );
  const users = await auth.admin.listUsers();

  return <p>{admin.email} can manage {users.length} users.</p>;
}
```

The Go backend remains the final authorization boundary. The role helper only
controls the Next.js page experience.

## Client Components

Use `@authserver/sdk` and `@authserver/sdk-react` in Client Components:

```tsx
"use client";

import { AuthClient } from "@authserver/sdk";
import { AuthProvider } from "@authserver/sdk-react";

const auth = new AuthClient({ baseUrl: "/api" });

export function Providers({ children }: { children: React.ReactNode }) {
  return <AuthProvider client={auth}>{children}</AuthProvider>;
}
```

Login, signup, and logout are best performed in Client Components or through a
Next.js Route Handler that explicitly forwards `Set-Cookie` headers. A server
`fetch()` call alone does not copy those response cookies into the browser.

## Security

- Do not expose `AUTH_SERVER_URL` with a `NEXT_PUBLIC_` prefix.
- Do not store session tokens in `localStorage`.
- Use HTTPS and set `AUTH_SECURE_COOKIES=true` in production.
- Keep authorization checks in the Go API even when using route helpers.

See [`sdk-next-demo`](../../demos/sdk-next-demo) for a complete runnable
Next.js example.
