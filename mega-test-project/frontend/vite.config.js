// =============================================================================
// frontend/vite.config.js – Vite Build Configuration
// =============================================================================
// PURPOSE: Configures the Vite dev server and build settings.
//
// ⚠️  INTENTIONAL ISSUES IN THIS FILE:
//   1. BAD: CORS is set to allow ALL origins (*) — SonarQube: "Make sure allowing
//            any origin is safe here"
//   2. BAD: No HTTPS configured — dev server runs on plain HTTP
//   3. BAD: Source maps enabled in production config — exposes internal code
// =============================================================================

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
    plugins: [react()],

    server: {
        host: '0.0.0.0',   // Needed for Docker
        port: 5173,

        // BAD: Proxy allows all origins — CORS wildcard is a security risk
        cors: true,          // BAD: Should specify exact allowed origins, not true/wildcard

        proxy: {
            '/api': {
                target: 'http://backend-node:3000',
                changeOrigin: true,
                // BAD: No SSL validation in proxy
                secure: false
            }
        }
    },

    build: {
        // BAD: Source maps expose internal code structure to attackers
        sourcemap: true,    // BAD: Should be false in production

        outDir: 'dist',
    }
})
