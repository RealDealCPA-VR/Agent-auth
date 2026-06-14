/** @type {import('next').NextConfig} */
const nextConfig = {
  // Strict mode surfaces accidental side-effects early; the admin UI is small
  // enough that the dev double-invoke is not a concern.
  reactStrictMode: true,
  // We never expose secrets through the build; the only public config is the
  // API base URL, which is read at runtime via NEXT_PUBLIC_API_URL.
  poweredByHeader: false,
};

export default nextConfig;
