/** @type {import('next').NextConfig} */
const nextConfig = {
  // Strict mode surfaces accidental side-effects early; the admin UI is small
  // enough that the dev double-invoke is not a concern.
  reactStrictMode: true,
  // We never expose secrets through the build; the only public config is the API
  // base URL. NEXT_PUBLIC_API_URL is INLINED into the client bundle at build time
  // (not read at runtime), so it must be set before `next build` — changing it
  // requires a rebuild.
  poweredByHeader: false,
};

export default nextConfig;
