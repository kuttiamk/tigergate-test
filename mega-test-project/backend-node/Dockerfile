# =============================================================================
# backend-node/Dockerfile
# =============================================================================
# PURPOSE: Builds the Node.js Express API server.
#
# ⚠️  INTENTIONAL ISSUES:
#   1. BAD: node:16 is an EOL (end of life) version — has known vulnerabilities
#   2. BAD: Running as root (no USER directive)
#   3. BAD: npm install installs ALL deps including devDependencies
#   4. BAD: No health check defined
# =============================================================================

# BAD: node:16 is end-of-life. Should use node:20-alpine
FROM node:16

WORKDIR /app

COPY package*.json ./

# BAD: installs devDependencies too (use --only=production for prod builds)
RUN npm install

COPY . .

EXPOSE 3000

# BAD: Running as root user — if app is compromised, attacker has root shell
CMD ["node", "server.js"]
