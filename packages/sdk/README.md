# `@authserver/sdk`

TypeScript client for the authserver JSON API. It uses the server's HTTP-only
session cookie and automatically sends the CSRF token for state-changing calls.

```ts
import { AuthClient } from "@authserver/sdk";

const auth = new AuthClient({ baseUrl: "/api" });
const user = await auth.login("user@example.com", "a-password-at-least-10-chars");
```

For local React development, use a dev-server proxy so requests go through the
same origin. Do not store the session cookie or passwords in `localStorage`.
