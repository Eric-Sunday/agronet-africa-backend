# ─────────────────────────────────────────────────────────────────────────────
# AgroNet Africa Backend — Production Dockerfile
# Multi-stage build: lean final image, no devDependencies, non-root user
# Target: Google Cloud Run (fully managed, auto-scaling)
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Dependency installer ────────────────────────────────────────────
FROM node:20-alpine AS deps

# Install only production dependencies in an isolated layer
WORKDIR /app

COPY package.json package-lock.json ./

# ci is faster + reproducible; --omit=dev keeps image lean
RUN npm ci --omit=dev

# ── Stage 2: Production runtime ───────────────────────────────────────────────
FROM node:20-alpine AS runner

# Security: set non-root user so the container cannot write to the host
RUN addgroup --system --gid 1001 nodejs \
 && adduser  --system --uid 1001 nodeapp

WORKDIR /app

# Copy only what we need from the deps stage (no devDependencies)
COPY --from=deps /app/node_modules ./node_modules

# Copy application source
COPY server.js  ./server.js
COPY db.js      ./db.js
COPY package.json ./package.json

# Cloud Run injects PORT at runtime (default 8080); our server.js reads it
ENV PORT=8080
ENV NODE_ENV=production

# Expose the port Cloud Run will route traffic to
EXPOSE 8080

# Drop root privileges
USER nodeapp

# Healthcheck — Cloud Run will probe / to verify the container is healthy
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/ || exit 1

# Start the server
CMD ["node", "server.js"]
