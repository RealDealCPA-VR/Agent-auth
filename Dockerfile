# syntax=docker/dockerfile:1

# --- Build stage -------------------------------------------------------------
FROM node:20-bookworm-slim AS build
WORKDIR /app

# argon2 needs a toolchain to build its native binding.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

RUN corepack enable

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY tsconfig.json drizzle.config.ts ./
COPY src ./src
COPY drizzle ./drizzle
RUN pnpm build \
  && pnpm prune --prod

# --- Runtime stage -----------------------------------------------------------
FROM node:20-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app

# Run as the unprivileged built-in node user.
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/drizzle ./drizzle
COPY --chown=node:node package.json ./

USER node
EXPOSE 8080

# Container-level healthcheck hits the app's liveness endpoint.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/index.js"]
