import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Authserver Next.js SDK Demo",
  description: "A small Next.js application using the authserver SDK",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
