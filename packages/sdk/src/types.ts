export type UserRole = "user" | "admin";

export interface User {
  id: string;
  email: string;
  role: UserRole;
  disabled: boolean;
  createdAt: string;
}

export interface Session {
  id: string;
  createdAt: string;
  expiresAt: string;
  userAgent: string;
  ip: string;
}

export interface MessageResponse {
  message: string;
}

export interface OkResponse {
  ok: true;
}
