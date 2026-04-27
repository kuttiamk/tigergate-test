// =============================================================================
// frontend/src/App.jsx – Main React Application
// =============================================================================
// PURPOSE: This is the main React component. It contains multiple pages:
//   - Home page
//   - User List (fetches from Node.js backend)
//   - Product List (fetches from Python backend)
//   - Search (has XSS vulnerability)
//   - Login form (sends plain text password)
//
// ⚠️  INTENTIONAL ISSUES IN THIS FILE:
//   1. BAD: dangerouslySetInnerHTML used without sanitization = XSS vulnerability
//          SonarQube: "Make sure this content is properly sanitized"
//   2. BAD: Password sent over HTTP (not HTTPS) in login form
//   3. BAD: Hardcoded API base URL (should come from environment)
//   4. BAD: No input validation before sending to API
//   5. BAD: Console.log used for debugging (exposes data in browser console)
//   6. BAD: API key visible in frontend code
//   7. BAD: Long component function (> 100 lines) — code smell
//   8. BAD: Direct DOM manipulation with eval() — dangerous!
// =============================================================================

import { useState, useEffect } from 'react'

// BAD: API URL hardcoded — should be from import.meta.env.VITE_API_URL
const API_BASE = 'http://localhost:3000'
const PYTHON_API = 'http://localhost:5000'
const JAVA_API = 'http://localhost:8080'

// BAD: Secret API key hardcoded in frontend source code!
// Anyone who opens DevTools → Sources can see this.
// SonarQube will flag: "Make sure this secret is properly protected"
const API_KEY = 'sk-megacorp-secret-api-key-12345-abcdef'

// SVG Icons
const Icons = {
    Home: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><polyline points="9 22 9 12 15 12 15 22" /></svg>,
    Users: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" /></svg>,
    Database: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" /><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" /></svg>,
    Search: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>,
    Lock: () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
};

// =============================================================================
// 🔴 XSS VULNERABLE COMPONENT
// SonarQube Rule: javascript:S5247 – Disabling HTML auto-escaping is risky
// =============================================================================
function XssVulnerableSearch() {
    const [query, setQuery] = useState('')
    const [result, setResult] = useState('')

    const handleSearch = () => {
        // BAD: User input injected directly into HTML without sanitization!
        // If user types: <img src=x onerror=alert('XSS')>
        // That script runs in the browser!
        setResult(`You searched for: <strong>${query}</strong>`)

        // BAD: console.log exposes search queries in browser console
        console.log('User searched for:', query)  // BAD: Information leakage
    }

    return (
        <div className="card">
            <h2><Icons.Search /> Search (XSS Vulnerable)</h2>
            <div className="input-group">
                <input
                    type="text"
                    placeholder="Try: <img src=x onerror=alert('XSS')>"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                />
            </div>
            <button onClick={handleSearch}>Execute Search</button>

            {/* =================================================================
          🔴 BAD: dangerouslySetInnerHTML renders raw HTML from user input!
          This is a classic Cross-Site Scripting (XSS) vulnerability.
          SonarQube: "Make sure this content is properly sanitized"
          FIX WOULD BE: Use a library like DOMPurify.sanitize(result)
          ================================================================= */}
            {result && (
                <div style={{ marginTop: '20px', padding: '16px', background: 'rgba(0,255,170,0.05)', borderRadius: '8px' }}>
                    <div dangerouslySetInnerHTML={{ __html: result }} />
                </div>
            )}
        </div>
    )
}

// =============================================================================
// Login Form – Bad Practices
// =============================================================================
function LoginForm() {
    const [username, setUsername] = useState('')
    const [password, setPassword] = useState('')
    const [message, setMessage] = useState('')
    const [isSuccess, setIsSuccess] = useState(false)

    const handleLogin = async () => {
        // BAD: No input validation — empty fields sent to server
        // BAD: Password logged to console!
        console.log('Attempting login with:', username, password)  // BAD: Password exposed!

        try {
            const res = await fetch(`${API_BASE}/api/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': API_KEY  // BAD: Secret key in every request header
                },
                // BAD: No CSRF token
                body: JSON.stringify({ username, password })
            })

            const data = await res.json()

            if (res.ok) {
                // BAD: JWT token stored in localStorage — vulnerable to XSS theft
                // SonarQube: "Storing sensitive data in localStorage is risky"
                localStorage.setItem('jwt_token', data.token)   // BAD: Use httpOnly cookies!
                localStorage.setItem('user_role', data.role)     // BAD: Role tampered client-side
                localStorage.setItem('username', username)
                setIsSuccess(true)
                setMessage(`Welcome ${username}! Token: ${data.token}`)  // BAD: Token shown in UI!
            } else {
                setIsSuccess(false)
                setMessage(data.error || 'Login failed')
            }
        } catch (err) {
            // BAD: Generic error — no useful feedback, and no logging
            setIsSuccess(false)
            setMessage('Network Error: Something went wrong')  // BAD: Silent failure
        }
    }

    return (
        <div className="card" style={{ maxWidth: '400px', margin: '0 auto' }}>
            <h2><Icons.Lock /> Access Portal</h2>
            <div className="input-group">
                <input type="text" placeholder="Username (e.g. admin)" value={username} onChange={e => setUsername(e.target.value)} />
            </div>
            <div className="input-group">
                {/* BAD: Password field value is logged above */}
                <input type="password" placeholder="Password (e.g. password123)" value={password} onChange={e => setPassword(e.target.value)} />
            </div>
            <button onClick={handleLogin} style={{ width: '100%' }}>Authenticate</button>

            {message && (
                <div className={isSuccess ? 'success' : 'error'}>
                    {message}
                </div>
            )}
        </div>
    )
}

// =============================================================================
// Users List – Fetches from Node.js Backend
// =============================================================================
function UsersList() {
    const [users, setUsers] = useState([])
    const [error, setError] = useState(null)
    const [search, setSearch] = useState('')

    // BAD: Fetches ALL users without pagination — N+1 style over-fetching
    useEffect(() => {
        fetch(`${API_BASE}/api/users`)
            .then(res => res.json())
            .then(data => {
                console.log('Fetched users:', data)   // BAD: PII data in console
                setUsers(data)
            })
            .catch(err => {
                // BAD: Swallowed error — user never sees meaningful message
                console.error(err)                    // BAD: Raw error to console
                setError('Failed to load users from API')
            })
    }, [])

    // BAD: SQL-injection-like string concatenation in URL — should use params
    const handleSearch = () => {
        fetch(`${API_BASE}/api/users?search=${search}`)   // BAD: Unencoded query string
            .then(res => res.json())
            .then(data => setUsers(data))
            .catch(() => { setError('Search failed') })  // BAD: Silent failure
    }

    return (
        <div className="card">
            <h2><Icons.Users /> Users Database (Node.js)</h2>
            {error && <div className="error">{error}</div>}

            <div style={{ display: 'flex', gap: 12, marginBottom: 24, padding: '16px', background: 'rgba(0,0,0,0.3)', borderRadius: '12px' }}>
                <input style={{ margin: 0 }} placeholder="Search users by name..." value={search} onChange={e => setSearch(e.target.value)} />
                <button onClick={handleSearch}>Filter</button>
            </div>

            <div className="table-container">
                <table>
                    <thead><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr></thead>
                    <tbody>
                        {users.length > 0 ? users.map(u => (
                            <tr key={u.id}>
                                <td><span className="tag">#{u.id}</span></td>
                                <td><strong>{u.username}</strong></td>
                                <td style={{ color: 'var(--accent-cyan)' }}>{u.email}</td>
                                {/* BAD: Role displayed from API response with no sanitization */}
                                <td dangerouslySetInnerHTML={{ __html: `<span class="tag ${u.role === 'admin' ? 'admin' : ''}">${u.role}</span>` }} />  {/* BAD: XSS again! */}
                            </tr>
                        )) : (
                            <tr><td colSpan="4" style={{ textAlign: 'center', opacity: 0.5 }}>No users loaded. Ensure backend is running.</td></tr>
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    )
}

// =============================================================================
// Products List – Fetches from Python (Flask) Backend
// =============================================================================
function ProductsList() {
    const [products, setProducts] = useState([])

    useEffect(() => {
        // BAD: No timeout set — hangs indefinitely if server is slow
        fetch(`${PYTHON_API}/api/products`)
            .then(r => r.json())
            .then(d => setProducts(d))
            .catch(e => console.error(e))  // BAD: Silent failure
    }, [])

    return (
        <div className="card">
            <h2><Icons.Database /> Inventory (Python Flask)</h2>
            <div className="table-container">
                <table>
                    <thead><tr><th>Product Name</th><th>Price</th><th>Stock Level</th></tr></thead>
                    <tbody>
                        {products.length > 0 ? products.map((p, i) => (
                            // BAD: Using array index as key — causes rendering bugs on reorder
                            <tr key={i}>
                                <td><strong>{p.name}</strong></td>
                                <td style={{ color: 'var(--accent-success)', fontWeight: 'bold' }}>${p.price}</td>
                                <td>{p.stock} units</td>
                            </tr>
                        )) : (
                            <tr><td colSpan="3" style={{ textAlign: 'center', opacity: 0.5 }}>No tracking data. Start Python backend.</td></tr>
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    )
}

// =============================================================================
// Main App – Navigation + Page Routing (manual, no React Router used)
// BAD: No React Router — manual state-based routing is an anti-pattern
// =============================================================================
export default function App() {
    const [page, setPage] = useState('home')

    // BAD: Eval used to "dynamically" resolve page names — Remote Code Execution risk!
    // SonarQube: "eval() should not be used — it executes arbitrary code"
    const getPageTitle = (p) => {
        try {
            return eval(`"${p.charAt(0).toUpperCase() + p.slice(1)}"`)  // 🔴 BAD: eval() is NEVER safe!
        } catch (e) {
            return p
        }
    }

    return (
        <div className="app">
            <nav>
                <div className="brand">MegaCorp™ Security</div>
                <a href="#" className={page === 'home' ? 'active' : ''} onClick={() => setPage('home')}>Home</a>
                <a href="#" className={page === 'users' ? 'active' : ''} onClick={() => setPage('users')}>Users</a>
                <a href="#" className={page === 'products' ? 'active' : ''} onClick={() => setPage('products')}>Products</a>
                <a href="#" className={page === 'search' ? 'active' : ''} onClick={() => setPage('search')}>Search</a>
                <a href="#" className={page === 'login' ? 'active' : ''} onClick={() => setPage('login')}>Login</a>
            </nav>

            {page !== 'home' && <h1>{getPageTitle(page)} Module</h1>}

            {page === 'home' && <HomePage />}
            {page === 'users' && <UsersList />}
            {page === 'products' && <ProductsList />}
            {page === 'search' && <XssVulnerableSearch />}
            {page === 'login' && <LoginForm />}
        </div>
    )
}

// =============================================================================
// Home Page Component
// =============================================================================
function HomePage() {
    return (
        <div className="hero">
            <h1>Target Simulator</h1>
            <p>Welcome to the <strong>MegaCorp CNAPP Integration Environment</strong>. This application is deeply embedded with intentional vulnerabilities to validate TigerGate's SAST, DAST, and CWPP scanners.</p>

            <div className="features-grid">
                <div className="feature-box">
                    <h3><Icons.Users /> Node.js Backend</h3>
                    <p>Express server featuring SQL Injection, OS Command Execution, and Node deserialization endpoints.</p>
                    <div className="code-block">Base: http://localhost:3000</div>
                </div>

                <div className="feature-box">
                    <h3><Icons.Database /> Python Flask API</h3>
                    <p>Data lake endpoints suffering from SSTI payloads, Unrestricted File Uploads, and Path Traversal.</p>
                    <div className="code-block">Base: http://localhost:5000</div>
                </div>

                <div className="feature-box">
                    <h3><Icons.Lock /> React Frontend</h3>
                    <p>Client-side glassmorphism UI built on anti-patterns: eval() invocation, stored credentials, and Cross-Site-Scripting targets.</p>
                    <div className="code-block">State: Active</div>
                </div>
            </div>

            <div className="card" style={{ marginTop: '40px', textAlign: 'left' }}>
                <h2 style={{ fontSize: '1.4rem' }}>Security Notification</h2>
                <div className="error" style={{ marginTop: 0 }}>
                    <strong>Warning:</strong> Never deploy this configuration in production. By proceeding via the navigation menu, you acknowledge active risk triggers.
                </div>
            </div>
        </div>
    )
}
