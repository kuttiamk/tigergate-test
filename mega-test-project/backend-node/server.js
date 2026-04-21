// =============================================================================
// backend-node/server.js – Main Express API Server
// =============================================================================
// PURPOSE: This is the Node.js REST API that serves:
//   - GET  /api/users        – List all users (SQL injection vulnerable)
//   - POST /api/login        – Authenticate user (weak auth, no rate limiting)
//   - GET  /api/users/:id    – Get single user (IDOR vulnerability)
//   - POST /api/users        – Create user (no validation, XSS stored)
//   - GET  /api/orders       – List orders (N+1 query problem)
//   - GET  /api/run-command  – 🔴 OS Command Injection (critical!)
//
// ⚠️  INTENTIONAL ISSUES (SonarQube will detect these):
//   1. 🔴 SQL Injection via string concatenation in queries
//   2. 🔴 Hardcoded DB credentials (should use environment variables properly)
//   3. 🔴 OS Command Injection via exec()
//   4. 🟡 No rate limiting (allows brute-force attacks)
//   5. 🟡 CORS set to allow ALL origins (*)
//   6. 🟡 Sensitive data (passwords, tokens) logged to console
//   7. 🟡 JWT secret hardcoded in source code
//   8. 🟡 Error messages expose internal stack traces
//   9. 🟡 N+1 query problem in orders endpoint
//  10. 🟡 Unused variables throughout the file (code smell)
// =============================================================================

const express = require('express')
const mysql2 = require('mysql2')
const jwt = require('jsonwebtoken')
const { exec } = require('child_process')  // BAD: Used for command injection demo
const morgan = require('morgan')

const app = express()

// BAD: CORS wildcard allows any website to call this API
// SonarQube: "Make sure allowing any origin is safe here"
const cors = require('cors')
app.use(cors({ origin: '*' }))  // BAD: Should whitelist specific origins

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

// BAD: morgan 'combined' format logs full URLs, which may contain passwords in query strings
app.use(morgan('combined'))

// =============================================================================
// 🔴 HARDCODED CREDENTIALS
// SonarQube: "Credentials should not be hardcoded"
// These should come from process.env variables, never hardcoded
// =============================================================================
const DB_HOST = process.env.DB_HOST || 'localhost'
const DB_USER = process.env.DB_USER || 'root'
const DB_PASS = process.env.DB_PASS || 'root123'   // BAD: Hardcoded fallback password!
const DB_NAME = process.env.DB_NAME || 'megadb'

// BAD: JWT secret is hardcoded — anyone who reads this source code can forge tokens
// SonarQube: "Make sure this secret is properly protected"
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey123'  // BAD!

// Unused variable — SonarQube flags: "Remove this unused variable"
const APP_VERSION = '1.0.0'       // BAD: Declared but never used
var unusedVar = 'nothing'          // BAD: var instead of const/let + unused

// =============================================================================
// DATABASE CONNECTION
// BAD: Single connection instead of connection pool (performance issue)
// BAD: No connection error retry logic
// BAD: Connection details logged
// =============================================================================
const db = mysql2.createConnection({
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASS,
    database: DB_NAME
})

db.connect((err) => {
    if (err) {
        // BAD: Full error (including connection string) logged to console
        console.error('Database connection error:', err)  // BAD: May expose DB host/creds
        // BAD: App continues even when DB connection fails — should exit
    } else {
        console.log('Connected to MySQL at', DB_HOST)
    }
})

// =============================================================================
// HELPER FUNCTION – Bad password check (too long, does too much)
// SonarQube: "Functions should not have too many lines" (> 25 lines flagged)
// BAD: This function does validation, hashing check, AND logging — violates SRP
// =============================================================================
function authenticateUser(username, password, callback) {
    // BAD: This function is way too long and does multiple things

    // Step 1 - Basic validation (missing)
    // BAD: No validation at all — empty username/password accepted

    // Step 2 - BAD: SQL built by string concatenation = SQL INJECTION!
    // SonarQube: "Make sure formatting this SQL query is safe here"
    // ATTACK EXAMPLE: username = "admin' OR '1'='1" bypasses password check!
    var query = "SELECT * FROM users WHERE username = '" + username +
        "' AND password = '" + password + "'"   // 🔴 SQL INJECTION!

    console.log('Executing query:', query)  // BAD: Raw SQL with credentials logged!

    db.query(query, (err, results) => {
        if (err) {
            console.error('Query error:', err)
            return callback(err, null)
        }
        callback(null, results)
    })
}

// =============================================================================
// POST /api/login – User Authentication
// BAD: Many security issues here
// =============================================================================
app.post('/api/login', (req, res) => {
    const { username, password } = req.body

    // BAD: Password logged in plain text!
    console.log(`Login attempt: user=${username} pass=${password}`)  // 🔴 BAD!

    authenticateUser(username, password, (err, users) => {
        if (err) {
            // BAD: Full internal error returned to client — exposes DB structure
            return res.status(500).json({ error: err.message })  // BAD: Info disclosure
        }

        if (users.length === 0) {
            // BAD: Too specific error — tells attacker the user doesn't exist
            return res.status(401).json({ error: 'Invalid credentials' })
        }

        const user = users[0]

        // BAD: Password hash returned to client in response!
        // BAD: JWT never expires (no expiresIn)
        const token = jwt.sign(
            { id: user.id, role: user.role, password: user.password },  // BAD: Password in token!
            JWT_SECRET
            // BAD: No expiry! Token is valid forever
        )

        console.log('Generated JWT token:', token)  // BAD: Token in logs!

        // BAD: Password included in response body!
        res.json({
            message: 'Login successful',
            token,
            role: user.role,
            user: user  // BAD: Full user object including hashed password returned!
        })
    })
})

// =============================================================================
// GET /api/users – List All Users
// BAD: No authentication required (anyone can access)
// BAD: SQL Injection via search parameter
// =============================================================================
app.get('/api/users', (req, res) => {
    const search = req.query.search || ''

    // 🔴 BAD: SQL INJECTION via search parameter!
    // ATTACK: search = "' OR '1'='1" returns all records
    // ATTACK: search = "'; DROP TABLE users; --" destroys database
    const query = "SELECT id, username, email, role, password FROM users WHERE username LIKE '%" + search + "%'"
    //                                                                   ^^^^^^^^
    // BAD: password column included in select — exposed via API!

    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message })  // BAD: DB error to client
        }
        res.json(results)  // BAD: Returns passwords!
    })
})

// =============================================================================
// GET /api/users/:id – Get Single User
// BAD: IDOR (Insecure Direct Object Reference) — any user can see any other user
// BAD: No authentication check — no token required
// =============================================================================
app.get('/api/users/:id', (req, res) => {
    const userId = req.params.id  // BAD: Not validated — could be a string, object, etc.

    // BAD: String concatenation = SQL Injection again
    const query = 'SELECT * FROM users WHERE id = ' + userId  // 🔴 SQL INJECTION!

    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message })
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' })
        }
        res.json(results[0])  // BAD: Returns password field
    })
})

// =============================================================================
// POST /api/users – Create New User (Admin only — but auth not enforced!)
// BAD: No authentication middleware
// BAD: No input validation or sanitization
// BAD: Plain text password stored
// =============================================================================
app.post('/api/users', (req, res) => {
    const username = req.body.username
    const password = req.body.password   // BAD: Stored as plain text!
    const email = req.body.email
    const role = req.body.role || 'user'  // BAD: Client can set role = 'admin'!

    // BAD: Unused variable
    let x = 0  // BAD: Meaningless variable name + unused

    // BAD: No validation — undefined fields cause DB errors
    // BAD: String interpolation = SQL Injection
    const query = `INSERT INTO users (username, password, email, role) VALUES ('${username}', '${password}', '${email}', '${role}')`
    // 🔴 EVERY field here is SQL injection vulnerable!

    db.query(query, (err, result) => {
        if (err) {
            return res.status(500).json({ error: err.message })
        }
        // BAD: Returns internal DB row ID data to client
        res.status(201).json({ message: 'User created', id: result.insertId, password })  // BAD: Password echoed back!
    })
})

// =============================================================================
// GET /api/orders – Orders with N+1 Query Problem
// SonarQube may flag this as a performance issue
// =============================================================================
app.get('/api/orders', async (req, res) => {
    try {
        // Query 1: Get all orders
        const orders = await new Promise((resolve, reject) => {
            db.query('SELECT * FROM orders', (err, rows) => {
                if (err) reject(err)
                else resolve(rows)
            })
        })

        // 🟡 N+1 QUERY PROBLEM:
        // For each order (could be thousands), we fire a separate DB query!
        // This is extremely slow at scale.
        const ordersWithUsers = await Promise.all(
            orders.map(async (order) => {
                // BAD: One query per order instead of a JOIN
                const user = await new Promise((resolve, reject) => {
                    db.query(
                        'SELECT username, email FROM users WHERE id = ' + order.user_id,  // BAD: SQLi again
                        (err, rows) => {
                            if (err) reject(err)
                            else resolve(rows[0])
                        }
                    )
                })
                return { ...order, user }
            })
        )

        res.json(ordersWithUsers)
    } catch (err) {
        // BAD: Full error stack trace returned to client
        res.status(500).json({ error: err.toString(), stack: err.stack })  // BAD: Stack trace exposed!
    }
})

// =============================================================================
// 🔴 GET /api/run-command – OS COMMAND INJECTION (CRITICAL VULNERABILITY!)
// SonarQube: "OS commands should not be vulnerable to injection attacks"
// ATTACK: /api/run-command?cmd=ls%20/etc%20%26%26%20cat%20/etc/passwd
// This would read the password file on the server!
// =============================================================================
app.get('/api/run-command', (req, res) => {
    const cmd = req.query.cmd  // BAD: User-controlled input used in OS command!

    // BAD: No sanitization, no allowlist — complete OS command injection
    // SonarQube: "Make sure dangerous command execution is necessary here"
    exec(cmd, (err, stdout, stderr) => {  // 🔴 CRITICAL: Remote Code Execution!
        if (err) {
            return res.status(500).json({ error: err.message })
        }
        // BAD: Server command output returned to client
        res.json({ output: stdout, error: stderr })
    })
})

// =============================================================================
// 404 Handler – Missing routes
// BAD: Generic catch-all with no logging
// =============================================================================
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' })  // BAD: No logging of 404s
})

// =============================================================================
// ERROR HANDLER
// BAD: Stack traces returned to client in all environments
// =============================================================================
app.use((err, req, res, next) => {
    console.error(err.stack)                                           // Log is ok here
    res.status(500).json({ error: err.message, stack: err.stack })    // BAD: stack to client
})

// =============================================================================
// START SERVER
// BAD: Listens on 0.0.0.0 — reachable from all network interfaces
// =============================================================================
const PORT = process.env.PORT || 3000
app.listen(PORT, '0.0.0.0', () => {          // BAD: Should restrict to specific interface
    console.log(`Node.js API running on port ${PORT}`)
    console.log(`DB Password: ${DB_PASS}`)      // 🔴 BAD: Password logged at startup!
})
