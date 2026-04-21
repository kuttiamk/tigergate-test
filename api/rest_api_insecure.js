// =============================================================================
// api/rest_api_insecure.js – TigerGate CNAPP: REST API Security (OWASP API Top 10)
// =============================================================================
// PURPOSE: Demonstrates all 10 OWASP API Security Top 10 (2023) vulnerabilities
// in a realistic e-commerce REST API. Each endpoint maps to a specific API risk.
//
// OWASP API SECURITY TOP 10 (2023):
//   API1:  Broken Object Level Authorization (BOLA/IDOR)
//   API2:  Broken Authentication
//   API3:  Broken Object Property Level Authorization (Mass Assignment)
//   API4:  Unrestricted Resource Consumption (No rate limiting)
//   API5:  Broken Function Level Authorization (Admin endpoints exposed)
//   API6:  Unrestricted Access to Sensitive Business Flows
//   API7:  Server-Side Request Forgery (SSRF)
//   API8:  Security Misconfiguration (CORS *, verbose errors)
//   API9:  Improper Inventory Management (shadow/undocumented endpoints)
//   API10: Unsafe Consumption of APIs (trusting external data without validation)
// =============================================================================

const express = require('express');
const axios = require('axios');
const fs = require('fs');
const app = express();
app.use(express.json());

// BAD: Hardcoded JWT secret
const JWT_SECRET = 'megacorp_api_secret_123';

// ── API8: Security Misconfiguration — Permissive CORS ──────────────────────
// 🔴 API8: Allows any origin to call this API (including attacker sites)
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');         // 🔴 API8: Wildcard CORS
    res.header('Access-Control-Allow-Methods', '*');        // 🔴 API8: All methods allowed
    res.header('Access-Control-Allow-Headers', '*');        // 🔴 API8: All headers allowed
    res.header('X-Powered-By', 'Express 4.17.1');          // 🔴 API8: Reveals framework
    res.header('Server', 'Ubuntu 20.04 / Node 14.x');      // 🔴 API8: Reveals OS + runtime
    next();
});

// ── API1: Broken Object Level Authorization (BOLA / IDOR) ──────────────────
// 🔴 API1: user ID comes from URL param — any logged-in user can read any account
app.get('/api/v1/users/:userId', (req, res) => {
    const { userId } = req.params;
    // 🔴 BAD: No check that req.user.id === userId
    // BOLA payload: GET /api/v1/users/1 while logged in as user 2 → see user 1's data
    const user = {
        id: userId, email: 'victim@megacorp.com', ssn: '123-45-6789',
        creditCard: '4111111111111111', cvv: '123'
    };
    res.json(user);   // 🔴 API1: Exposes full PII including SSN and card to any caller!
});

// ── API2: Broken Authentication ─────────────────────────────────────────────
// 🔴 API2: No brute-force protection, weak token, no expiry check
app.post('/api/v1/auth/login', (req, res) => {
    const { username, password } = req.body;
    // 🔴 API2: No rate limiting — unlimited login attempts (brute-forceable)
    // 🔴 API2: Password comparison in plaintext (no hashing)
    if (username === 'admin' && password === 'admin123') {
        // 🔴 API2: Static token — never expires, no refresh flow
        res.json({ token: 'STATIC_ADMIN_TOKEN_ABC123', role: 'admin' });
    } else {
        // 🔴 API8: Verbose error reveals whether username exists
        res.status(401).json({ error: `User ${username} not found or wrong password` });
    }
});

// ── API3: Broken Object Property Level Authorization (Mass Assignment) ───────
// 🔴 API3: Accepts ALL fields from request body including 'role' and 'isAdmin'
app.put('/api/v1/users/:userId', (req, res) => {
    const { userId } = req.params;
    const updateData = req.body;  // 🔴 API3: Spreads ALL user-provided fields onto model
    // Attacker sends: {"role": "admin", "isAdmin": true, "creditBalance": 99999}
    const user = Object.assign({ id: userId, role: 'user', isAdmin: false }, updateData);
    //                          ^^^^ Replaced entirely by attacker input!
    res.json({ updated: user });   // 🔴 API3: Confirms privilege escalation!
});

// ── API4: Unrestricted Resource Consumption (No Rate Limiting) ───────────────
// 🔴 API4: No rate limiting on expensive search endpoint — DoS via mass requests
app.get('/api/v1/search', async (req, res) => {
    const { q, page = 1, limit = 1000 } = req.query;
    // 🔴 API4: limit up to 1000 at a time with no cap — enables data harvesting
    // 🔴 API4: No request throttling — 10,000 req/s possible
    const results = Array.from({ length: Number(limit) }, (_, i) => ({
        id: i + 1, name: `Product ${i}`, price: Math.random() * 1000
    }));
    res.json({ total: results.length, data: results });
});

// ── API5: Broken Function Level Authorization (Admin endpoint exposed) ────────
// 🔴 API5: Admin function accessible by any authenticated user (no role check)
app.delete('/api/v1/admin/users/:userId', (req, res) => {
    // 🔴 API5: Missing authorization check: if (req.user.role !== 'admin') return 403
    const { userId } = req.params;
    res.json({ deleted: userId, message: 'User deleted — admin check BYPASSED' });
});

app.get('/api/v1/admin/export-all-users', (req, res) => {
    // 🔴 API5: Exports ALL user PII to any caller — no admin check
    const users = [{ id: 1, email: 'ceo@megacorp.com', ssn: '999-99-9999' }];
    res.json({ users });   // 🔴 API5: Full PII dump via admin endpoint bypass
});

// ── API6: Unrestricted Access to Sensitive Business Flows ────────────────────
// 🔴 API6: Purchase endpoint with no business logic guards
app.post('/api/v1/purchase', (req, res) => {
    const { productId, quantity, couponCode } = req.body;
    // 🔴 API6: No check if coupon already used — unlimited coupon stacking
    // 🔴 API6: No inventory check — can over-purchase
    // 🔴 API6: quantity has no cap — buy -1 items (negative balance attack)!
    const price = 100 * quantity;            // Negative quantity = negative price = refund?
    const discount = couponCode ? 0.9 : 1;  // 🔴 API6: Coupon valid infinite times
    res.json({ total: price * discount, quantityPurchased: quantity });
});

// ── API7: Server-Side Request Forgery (SSRF) ─────────────────────────────────
// 🔴 API7: Fetches user-controlled URL — enables SSRF to internal services
app.get('/api/v1/proxy', async (req, res) => {
    const { url } = req.query;
    try {
        // 🔴 API7: No URL allowlist — attacker can hit IMDS, internal services
        // Payload: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
        const response = await axios.get(url, { timeout: 5000 });
        res.json({ data: response.data });   // 🔴 Returns IMDS credentials!
    } catch (e) {
        res.status(500).json({ error: e.message, stack: e.stack });  // 🔴 API8: Stack trace!
    }
});

// ── API9: Improper Inventory Management (shadow endpoints) ───────────────────
// 🔴 API9: Undocumented endpoints not in OpenAPI spec — escape security review
app.get('/api/v2-beta/debug/config', (req, res) => {
    // 🔴 API9: Shadow debug endpoint — not in swagger.yaml, not secured
    res.json({
        db: 'postgresql://admin:secret@internal-db:5432/prod',   // 🔴 API9: Exposes connection strings!
        jwtSecret: JWT_SECRET,
        env: process.env   // 🔴 API9: Exposes ALL environment variables!
    });
});

// ── API10: Unsafe Consumption of External APIs ────────────────────────────────
// 🔴 API10: Trusts external API response and executes it without validation
app.post('/api/v1/webhook/payment-processor', async (req, res) => {
    const webhookData = req.body;
    // 🔴 API10: No signature verification on webhook (no HMAC check)
    // Attacker sends fake 'payment_success' webhook → free goods
    if (webhookData.event === 'payment_success') {
        // 🔴 API10: Blindly trusted external data triggers fulfillment
        console.log(`Order fulfilled for: ${webhookData.orderId}`);  // No validation!
        res.json({ fulfilled: webhookData.orderId });
    }
    // 🔴 API10: Also: response from external API piped directly to eval()
    const externalData = webhookData.template;
    if (externalData) eval(externalData);  // 🔴 API10 + CWE-94: eval() of external data!
});

app.listen(3001, () => {
    console.log('REST API Insecure Server running on :3001');
    console.log(`JWT Secret: ${JWT_SECRET}`);  // 🔴 API8: Secret logged at startup!
});
