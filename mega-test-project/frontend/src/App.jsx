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
        setResult(`You searched for: ${query}`)

        // BAD: console.log exposes search queries in browser console
        console.log('User searched for:', query)  // BAD: Information leakage
    }

    return (
        <div className="card">
            <h2>🔍 Search (XSS Vulnerable)</h2>
            <input
                type="text"
                placeholder="Try: <img src=x onerror=alert('XSS')>"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
            />
            <button onClick={handleSearch}>Search</button>

            {/* =================================================================
          🔴 BAD: dangerouslySetInnerHTML renders raw HTML from user input!
          This is a classic Cross-Site Scripting (XSS) vulnerability.
          SonarQube: "Make sure this content is properly sanitized"
          FIX WOULD BE: Use a library like DOMPurify.sanitize(result)
          ================================================================= */}
            {result && (
                <div dangerouslySetInnerHTML={{ __html: result }} />
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

            // BAD: JWT token stored in localStorage — vulnerable to XSS theft
            // SonarQube: "Storing sensitive data in localStorage is risky"
            localStorage.setItem('jwt_token', data.token)   // BAD: Use httpOnly cookies!
            localStorage.setItem('user_role', data.role)     // BAD: Role tampered client-side
            localStorage.setItem('username', username)

            setMessage(`Welcome ${username}! Token: ${data.token}`)  // BAD: Token shown in UI!
        } catch (err) {
            // BAD: Generic error — no useful feedback, and no logging
            setMessage('Something went wrong')  // BAD: Silent failure, no error details captured
        }
    }

    return (
        <div className="card">
            <h2>🔐 Login</h2>
            <input type="text" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
            {/* BAD: Password field value is logged above */}
            <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
            <button onClick={handleLogin}>Login</button>
            {message && <p>{message}</p>}
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
                setError('Failed to load users')
            })
    }, [])

    // BAD: SQL-injection-like string concatenation in URL — should use params
    const handleSearch = () => {
        fetch(`${API_BASE}/api/users?search=${search}`)   // BAD: Unencoded query string
            .then(res => res.json())
            .then(data => setUsers(data))
            .catch(() => { })  // BAD: Completely silent failure
    }

    if (error) return <div className="error">{error}</div>

    return (
        <div className="card">
            <h2>👥 Users (from Node.js API)</h2>
            <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
                <input placeholder="Search users..." value={search} onChange={e => setSearch(e.target.value)} />
                <button onClick={handleSearch}>Search</button>
            </div>
            <table>
                <thead><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr></thead>
                <tbody>
                    {users.map(u => (
                        <tr key={u.id}>
                            <td>{u.id}</td>
                            <td>{u.username}</td>
                            <td>{u.email}</td>
                            {/* BAD: Role displayed from API response with no sanitization */}
                            <td dangerouslySetInnerHTML={{ __html: u.role }} />  {/* BAD: XSS again! */}
                        </tr>
                    ))}
                </tbody>
            </table>
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
            <h2>🛒 Products (from Python Flask API)</h2>
            <table>
                <thead><tr><th>Name</th><th>Price</th><th>Stock</th></tr></thead>
                <tbody>
                    {products.map((p, i) => (
                        // BAD: Using array index as key — causes rendering bugs on reorder
                        <tr key={i}>
                            <td>{p.name}</td>
                            <td>${p.price}</td>
                            <td>{p.stock}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
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
            return eval(`"${p} page"`)  // 🔴 BAD: eval() is NEVER safe!
        } catch (e) {
            return p
        }
    }

    return (
        <div className="app">
            <nav>
                <span style={{ color: '#fff', fontWeight: 'bold', marginRight: 16 }}>🏢 MegaCorp</span>
                <a href="#" onClick={() => setPage('home')}>Home</a>
                <a href="#" onClick={() => setPage('users')}>Users</a>
                <a href="#" onClick={() => setPage('products')}>Products</a>
                <a href="#" onClick={() => setPage('search')}>Search</a>
                <a href="#" onClick={() => setPage('login')}>Login</a>
            </nav>

            <h1>{getPageTitle(page)}</h1>

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
        <div className="card">
            <h2>Welcome to MegaCorp Internal App</h2>
            <p>This app has intentional security vulnerabilities for SonarQube and Tigergate testing.</p>
            <p>APIs available:</p>
            <ul>
                <li>Node.js API: <a href="http://localhost:3000/api/users">http://localhost:3000/api/users</a></li>
                <li>Python API: <a href="http://localhost:5000/api/products">http://localhost:5000/api/products</a></li>
                <li>Java API: <a href="http://localhost:8080/api/orders">http://localhost:8080/api/orders</a></li>
                <li>PHP App: <a href="http://localhost:8888">http://localhost:8888</a></li>
            </ul>
        </div>
    )
}
