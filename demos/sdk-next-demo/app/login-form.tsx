"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { AuthClient } from "@authserver/sdk";

const auth = new AuthClient({ baseUrl: "/api" });

export function LoginForm() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    try { await auth.login(email, password); router.refresh(); }
    catch (error) { setError(error instanceof Error ? error.message : "Sign-in failed"); }
  }

  return <section className="card narrow"><h2>Sign in</h2><form onSubmit={submit}>
    <label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label>
    <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
    <button type="submit">Sign in</button>
    {error && <p className="error">{error}</p>}
  </form></section>;
}
