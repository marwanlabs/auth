import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { AuthClient } from "@authserver/sdk";
import type { User, UserRole } from "@authserver/sdk";

export interface AuthContextValue {
  client: AuthClient;
  user: User | null;
  loading: boolean;
  refresh: () => Promise<User | null>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export interface AuthProviderProps {
  client: AuthClient;
  children: ReactNode;
}

export function AuthProvider({ client, children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    try {
      const nextUser = await client.me();
      setUser(nextUser);
      return nextUser;
    } catch {
      setUser(null);
      return null;
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void refresh(); }, [client]);

  const value = useMemo<AuthContextValue>(() => ({
    client,
    user,
    loading,
    refresh,
    logout: async () => {
      await client.logout();
      setUser(null);
    },
  }), [client, loading, user]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}

export function useRequireAuth() {
  const auth = useAuth();
  return { ...auth, authenticated: auth.user !== null };
}

export function useRequireRole(role: UserRole) {
  const auth = useRequireAuth();
  return { ...auth, authorized: auth.user?.role === role };
}
