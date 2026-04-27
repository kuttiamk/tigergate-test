# =============================================================================
# frontend/Dockerfile
# =============================================================================
# PURPOSE: Builds and serves the React + Vite frontend application.
#
# ⚠️  INTENTIONAL ISSUES IN THIS FILE:
#   1. BAD: Using `node:18` (a non-slim, large base image) — increases attack surface
#   2. BAD: Running as root (no USER instruction) — SonarQube flags this
#   3. BAD: No .dockerignore — copies node_modules (massive security + size risk)
#   4. BAD: VITE_API_URL hardcoded via ARG with a default — credentials in build args
# =============================================================================

# BAD: Should use node:18-alpine (smaller, fewer vulnerabilities)
FROM node:18

WORKDIR /app

# BAD: Copies everything including potential .env files and secrets
COPY . .

# Install dependencies (includes devDependencies — bad for production)
RUN npm install

# BAD: Should be "npm run build" for production, not "npm run dev"
# Exposing the dev server directly is a security risk
EXPOSE 5173

# BAD: Running Vite dev server — not a production setup
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
