import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { AuthClient, AuthServerError } from "@authserver/sdk";
import type { User, UserRole } from "@authserver/sdk";

export interface ServerAuthOptions {
  /** Server-side API root, e.g. http://127.0.0.1:8090/api. */
  baseUrl?: string;
  /** Route used when a required session is missing. */
  loginPath?: string;
  /** Route used when a user has the wrong role. */
  forbiddenPath?: string;
}

/** Create an SDK client that forwards the current Next.js request cookies. */
export async function createServerAuthClient(options: ServerAuthOptions = {}): Promise<AuthClient> {
  const cookieStore = await cookies();
  const cookieHeader = cookieStore.toString();
  const csrfToken = cookieStore.get("csrf_token")?.value;

  const serverFetch: typeof fetch = (input, init) => {
    const headers = new Headers(init?.headers);
    if (cookieHeader) headers.set("Cookie", cookieHeader);
    if (csrfToken) headers.set("X-CSRF-Token", csrfToken);
    return fetch(input, { ...init, headers });
  };

  return new AuthClient({
    baseUrl: options.baseUrl ?? process.env.AUTH_SERVER_URL ?? "http://127.0.0.1:8090/api",
    fetch: serverFetch,
  });
}

/** Return the current user, or null when the request is unauthenticated. */
export async function getServerUser(options: ServerAuthOptions = {}): Promise<User | null> {
  const client = await createServerAuthClient(options);
  try {
    return await client.me();
  } catch (error) {
    if (error instanceof AuthServerError && error.status === 401) return null;
    throw error;
  }
}

/** Require a signed-in user and redirect anonymous visitors to the login page. */
export async function requireUser(options: ServerAuthOptions = {}): Promise<User> {
  const user = await getServerUser(options);
  if (!user) redirect(options.loginPath ?? "/login");
  return user;
}

/** Require a role and redirect users without it to the forbidden page. */
export async function requireRole(role: UserRole, options: ServerAuthOptions = {}): Promise<User> {
  const user = await requireUser(options);
  if (user.role !== role) redirect(options.forbiddenPath ?? "/forbidden");
  return user;
}

export type { User, UserRole } from "@authserver/sdk";
