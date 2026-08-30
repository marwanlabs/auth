import { FormEvent, useEffect, useState } from "react";
import { AuthClient, AuthServerError, type User } from "@authserver/sdk";

const auth = new AuthClient({ baseUrl: "/api" });

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");

  useEffect(() => {
    auth.me().then(setUser).catch(() => setUser(null)).finally(() => setLoading(false));
  }, []);

  async function handleLogout() {
    await auth.logout();
    setUser(null);
    setMessage("You are signed out.");
  }

  if (loading) return <main className="shell"><p>Loading session…</p></main>;

  return (
    <main className="shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Authserver SDK</p>
          <h1>Simple React demo</h1>
          <p className="muted">A small app using the TypeScript SDK and the Go API.</p>
        </div>
        {user && <button className="secondary" onClick={handleLogout}>Sign out</button>}
      </header>
      {message && <p className="notice">{message}</p>}
      {user ? <Dashboard user={user} setUser={setUser} /> : <AuthForms onSignedIn={setUser} />}
    </main>
  );
}

function AuthForms({ onSignedIn }: { onSignedIn: (user: User) => void }) {
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      const user = mode === "login"
        ? await auth.login(email, password)
        : await auth.signup(email, password);
      onSignedIn(user);
    } catch (error) {
      setError(error instanceof AuthServerError ? error.message : "Request failed");
    }
  }

  return <section className="card narrow">
    <div className="tabs">
      <button className={mode === "login" ? "tab active" : "tab"} onClick={() => setMode("login")}>Sign in</button>
      <button className={mode === "signup" ? "tab active" : "tab"} onClick={() => setMode("signup")}>Create account</button>
    </div>
    <form onSubmit={submit}>
      <label>Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
      <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} minLength={10} required /></label>
      <button type="submit">{mode === "login" ? "Sign in" : "Create account"}</button>
      {error && <p className="error">{error}</p>}
    </form>
  </section>;
}

function Dashboard({ user, setUser }: { user: User; setUser: (user: User) => void }) {
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState("");

  async function loadUsers() {
    try { setUsers(await auth.admin.listUsers()); setError(""); }
    catch (error) { setError(error instanceof Error ? error.message : "Could not load users"); }
  }

  return <>
    <section className="card profile">
      <div><p className="eyebrow">Signed in</p><h2>{user.email}</h2></div>
      <span className="role">{user.role}</span>
    </section>
    <section className="card">
      <h2>SDK actions</h2>
      <div className="actions">
        <button onClick={async () => setUser(await auth.me())}>Refresh profile</button>
        {user.role === "admin" && <button className="secondary" onClick={loadUsers}>Load users</button>}
      </div>
      {error && <p className="error">{error}</p>}
      {user.role === "admin" && users.length > 0 && <UserList users={users} />}
    </section>
  </>;
}

function UserList({ users }: { users: User[] }) {
  return <div className="user-list">
    {users.map((user) => <div className="user-row" key={user.id}>
      <span>{user.email}</span><span className="muted">{user.role} · {user.disabled ? "disabled" : "active"}</span>
    </div>)}
  </div>;
}
