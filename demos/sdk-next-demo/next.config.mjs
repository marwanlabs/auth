import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: ["@authserver/sdk", "@authserver/sdk-next"],
  async rewrites() {
    return [{ source: "/api/:path*", destination: "http://127.0.0.1:8090/api/:path*" }];
  },
  webpack(config) {
    config.resolve.alias["@authserver/sdk"] = path.join(root, "../../packages/sdk/src");
    config.resolve.alias["@authserver/sdk-next/server"] = path.join(root, "../../packages/sdk-next/src/server.ts");
    return config;
  },
};

export default nextConfig;
