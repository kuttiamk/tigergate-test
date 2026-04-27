// =============================================================================
// industry/startup/misconfigured_saas.js – TigerGate CNAPP: Startup SaaS
// =============================================================================
// PURPOSE: Typical startup SaaS application with multi-tenancy data leakage,
// IDOR vulnerabilities, and missing rate limiting. Demonstrates the "move fast"
// security posture that creates massive CNAPP findings at scale.
//
// FINDINGS:
//   SaaS-001: Multi-tenancy isolation broken — tenantId from URL, not token
//   SaaS-002: IDOR — access any tenant's data by changing the ID
//   SaaS-003: No rate limiting on auth or API — account enumeration trivial
//   SaaS-004: Hardcoded admin bypass token in source code
//   SaaS-005: Verbose error messages reveal DB schema / stack traces
// =============================================================================
const express = require('express');
const app = express();
app.use(express.json());

// 🔴 SaaS-004: Hardcoded bypass token — anyone who finds this gets admin access
const ADMIN_BYPASS_TOKEN = "megacorp_super_admin_bypass_2024";

// Simulated tenant data store
const tenantData = {
    "tenant-001": { name: "Acme Corp", users: [{ email: "ceo@acme.com", ssn: "123-45" }], plan: "enterprise" },
    "tenant-002": { name: "Globex Inc", users: [{ email: "admin@globex.com", ssn: "987-65" }], plan: "starter" }
};

// ── SaaS-001/002: Tenant isolation broken — tenantId from URL param ──────────
// 🔴 SaaS-001: tenantId should come from JWT claims, NOT URL parameter
// 🔴 SaaS-002: IDOR — any authenticated user can access any tenant
app.get('/api/tenants/:tenantId/data', (req, res) => {
    const { tenantId } = req.params;  // 🔴 SaaS-002: IDOR — change :tenantId to any value!
    const token = req.headers.authorization;

    // 🔴 SaaS-004: Admin bypass — skip all checks with magic token
    if (token === ADMIN_BYPASS_TOKEN) {
        return res.json({ all_tenants: tenantData }); // Returns ALL tenant data!
    }

    // 🔴 SaaS-001: No verification that token.tenantId === req.params.tenantId
    // Should be: if (decodedToken.tenantId !== tenantId) return res.status(403).json(...)
    const data = tenantData[tenantId];
    if (!data) return res.status(404).json({ error: `Tenant ${tenantId} not found` }); // 🔴 Confirms tenant enumeration

    res.json(data);  // 🔴 Returns other tenant's SSNs and emails!
});

// ── SaaS-003: Login with no rate limiting — enumerate all accounts ───────────
const loginAttempts = {};  // No persistent tracking — resets on restart
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    // 🔴 SaaS-003: No lockout, no CAPTCHA, no delay — brute-force freely
    if (email === "admin@megacorp.com" && password === "admin") {
        res.json({ token: "admin-token", role: "admin", tenantId: "all" });
    } else {
        // 🔴 SaaS-005: Reveals whether account exists
        const exists = Object.values(tenantData).some(t => t.users.some(u => u.email === email));
        res.status(401).json({
            error: exists ? "Wrong password" : "Account not found",  // 🔴 Account enumeration!
            debug: { attempted_email: email, db_query: `SELECT * FROM users WHERE email='${email}'` }  // 🔴 Leaks DB query!
        });
    }
});

// ── SaaS-005: Global error handler reveals stack traces ──────────────────────
app.use((err, req, res, next) => {
    // 🔴 SaaS-005: Full stack trace + DB error messages sent to browser in production
    res.status(500).json({
        error: err.message,
        stack: err.stack,          // 🔴 Source file paths, line numbers
        sql: err.sql,             // 🔴 Database query that failed (ORM errors)
        config: process.env       // 🔴 ALL environment variables!
    });
});

app.listen(3002, () => console.log('SaaS server on :3002'));
