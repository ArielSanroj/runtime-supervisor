/** @type {import('next').NextConfig} */
const nextConfig = {
  env: {
    SUPERVISOR_API_URL: process.env.SUPERVISOR_API_URL ?? "http://localhost:8000",
  },
};
module.exports = nextConfig;
