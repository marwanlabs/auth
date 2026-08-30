"use client";

import { useRouter } from "next/navigation";
import { AuthClient } from "@authserver/sdk";

const auth = new AuthClient({ baseUrl: "/api" });

export function LogoutButton() {
  const router = useRouter();
  return <button className="secondary" onClick={async () => { await auth.logout(); router.refresh(); }}>Sign out</button>;
}
