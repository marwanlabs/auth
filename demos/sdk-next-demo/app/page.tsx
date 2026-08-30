import { createServerAuthClient, getServerUser } from "@authserver/sdk-next/server";
import { LoginForm } from "./login-form";
import { LogoutButton } from "./logout-button";

export default async function HomePage() {
  const user = await getServerUser();

  if (!user) {
    return <main className="shell"><Header /><LoginForm /></main>;
  }

  const users = user.role === "admin"
    ? await (await createServerAuthClient()).admin.listUsers()
    : [];

  return <main className="shell">
    <Header />
    <section className="card profile">
      <div><p className="eyebrow">Server Component session</p><h2>{user.email}</h2></div>
      <span className="role">{user.role}</span>
    </section>
    <section className="card">
      <h2>Next.js SDK is working</h2>
      <p className="muted">This user was loaded on the server with <code>getServerUser()</code>.</p>
      <LogoutButton />
    </section>
    {user.role === "admin" && <section className="card">
      <h2>Admin users</h2>
      <p className="muted">Loaded server-side with the admin SDK client.</p>
      <ul className="users">{users.map((item) => <li key={item.id}><span>{item.email}</span><span className="muted">{item.role}</span></li>)}</ul>
    </section>}
  </main>;
}

function Header() {
  return <header className="hero"><div><p className="eyebrow">@authserver/sdk-next</p><h1>Next.js demo</h1><p className="muted">SSR session checks with the Go authserver.</p></div></header>;
}
