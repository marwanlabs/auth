import { getCookie } from "./csrf.js";
import { AuthServerError } from "./errors.js";
import type { MessageResponse, OkResponse, Session, User, UserRole } from "./types.js";

export interface AuthClientOptions {
  /** API root, normally "/api" or "https://auth.example.com/api". */
  baseUrl?: string;
  /** Injectable fetch implementation for tests or server-side adapters. */
  fetch?: typeof fetch;
}

interface ApiUser {
  id: string;
  email: string;
  role: UserRole;
  disabled: boolean;
  created_at: string;
}

interface ApiSession {
  id: string;
  created_at: string;
  expires_at: string;
  user_agent: string;
  ip: string;
}

function mapUser(user: ApiUser): User {
  return { id: user.id, email: user.email, role: user.role, disabled: user.disabled, createdAt: user.created_at };
}

function mapSession(session: ApiSession): Session {
  return {
    id: session.id,
    createdAt: session.created_at,
    expiresAt: session.expires_at,
    userAgent: session.user_agent,
    ip: session.ip,
  };
}

export class AuthClient {
  private readonly baseUrl: string;
  private readonly fetcher: typeof fetch;

  constructor(options: AuthClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? "/api").replace(/\/$/, "");
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  async signup(email: string, password: string): Promise<User> {
    return mapUser(await this.request<ApiUser>("/signup", this.json("POST", { email, password })));
  }

  async login(email: string, password: string): Promise<User> {
    return mapUser(await this.request<ApiUser>("/login", this.json("POST", { email, password })));
  }

  async logout(): Promise<OkResponse> {
    return this.request<OkResponse>("/logout", this.json("POST"));
  }

  async me(): Promise<User> {
    return mapUser(await this.request<ApiUser>("/me"));
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<OkResponse> {
    return this.request<OkResponse>("/change-password", this.json("POST", {
      current_password: currentPassword,
      new_password: newPassword,
    }));
  }

  async listSessions(): Promise<Session[]> {
    const sessions = await this.request<ApiSession[]>("/sessions");
    return sessions.map(mapSession);
  }

  async revokeSession(sessionId: string): Promise<OkResponse> {
    return this.request<OkResponse>("/sessions/revoke", this.json("POST", { session_id: sessionId }));
  }

  async requestPasswordReset(email: string): Promise<MessageResponse> {
    return this.request<MessageResponse>("/password-reset/request", this.json("POST", { email }));
  }

  async confirmPasswordReset(token: string, newPassword: string): Promise<OkResponse> {
    return this.request<OkResponse>("/password-reset/confirm", this.json("POST", {
      token,
      new_password: newPassword,
    }));
  }

  readonly admin = {
    listUsers: async (): Promise<User[]> => {
      const users = await this.request<ApiUser[]>("/admin/users");
      return users.map(mapUser);
    },
    changeUserRole: async (userId: string, role: UserRole): Promise<User> =>
      mapUser(await this.request<ApiUser>("/admin/users/role", this.json("POST", { user_id: userId, role }))),
    changeUserStatus: async (userId: string, disabled: boolean): Promise<User> =>
      mapUser(await this.request<ApiUser>("/admin/users/status", this.json("POST", { user_id: userId, disabled }))),
    deleteUser: (userId: string): Promise<OkResponse> =>
      this.request<OkResponse>("/admin/users/delete", this.json("POST", { user_id: userId })),
  };

  private json(method: string, body?: unknown): RequestInit {
    return { method, body: body === undefined ? undefined : JSON.stringify(body) };
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const method = (init.method ?? "GET").toUpperCase();
    const headers = new Headers(init.headers);
    if (init.body !== undefined) headers.set("Content-Type", "application/json");
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
      const csrf = getCookie("csrf_token");
      if (csrf) headers.set("X-CSRF-Token", csrf);
    }

    let response: Response;
    try {
      response = await this.fetcher(`${this.baseUrl}${path}`, { ...init, headers, credentials: "include" });
    } catch (error) {
      throw new AuthServerError(error instanceof Error ? error.message : "Network request failed", 0);
    }

    let body: unknown = null;
    try { body = await response.json(); } catch { /* Empty response body. */ }
    if (!response.ok) {
      const data = body as { error?: unknown; code?: unknown } | null;
      const message = typeof data?.error === "string" ? data.error : `Request failed (${response.status})`;
      const code = typeof data?.code === "string" ? data.code : undefined;
      throw new AuthServerError(message, response.status, code);
    }
    return body as T;
  }
}
