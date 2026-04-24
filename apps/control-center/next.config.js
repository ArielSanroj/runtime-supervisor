/** @type {import('next').NextConfig} */
const nextConfig = {
  env: {
    SUPERVISOR_API_URL: process.env.SUPERVISOR_API_URL ?? "http://localhost:8000",
  },
  // Proxy /v1/* to the supervisor API so the browser hits a single origin.
  // Lets one ngrok tunnel cover landing + UI + API.
  async rewrites() {
    const target = process.env.SUPERVISOR_API_URL ?? "http://localhost:8099";
    return [
      { source: "/v1/:path*", destination: `${target}/v1/:path*` },
    ];
  },
};
module.exports = nextConfig;
