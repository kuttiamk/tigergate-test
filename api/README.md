# 📁 `api/` — API Security (OWASP API Top 10)

## What Is This?

APIs (Application Programming Interfaces) are how modern apps communicate — your mobile
app talks to a backend server via API. **API security** is about making sure those
communication channels can't be abused.

The **OWASP API Security Top 10 (2023)** is the definitive list of the most critical API
vulnerabilities. This folder contains a single Express.js app (`rest_api_insecure.js`)
that demonstrates **all 10** in one place.

## What's In This Folder?

| File | Purpose |
|------|---------|
| `rest_api_insecure.js` | Express.js API with all 10 OWASP API Security risks |

## All 10 OWASP API Security Risks — Explained Simply

### API1: Broken Object Level Authorization (BOLA / IDOR)
> Changing `/api/users/123` to `/api/users/124` lets you see another user's SSN and credit card.
```javascript
// ❌ BAD — No check that YOU own resource 124
app.get('/api/users/:userId', (req, res) => {
    return res.json(userData[req.params.userId]); // Anyone reads anyone's data!
});
```

### API2: Broken Authentication
> No rate limiting on login = unlimited password guessing. Static tokens that never expire.

### API3: Mass Assignment
> Sending `{"role": "admin"}` in a profile update actually makes you admin because ALL fields are accepted.
```javascript
const user = Object.assign({role: 'user'}, req.body); // req.body overwrites role!
```

### API4: Unrestricted Resource Consumption
> No rate limiting = attacker calls the same endpoint 10,000 times/second to crash it or harvest data.

### API5: Broken Function Level Authorization
> The `/api/admin/export-all-users` endpoint returns every user's SSN to anyone — no admin check.

### API6: Unrestricted Access to Sensitive Business Flows
> Passing `"quantity": -1` to the purchase endpoint could result in a credit (negative purchase).
> Using a coupon unlimited times (no "already used" check).

### API7: Server-Side Request Forgery (SSRF)
> `GET /api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`
> → Your server fetches the AWS metadata endpoint and returns your IAM credentials to the attacker!

### API8: Security Misconfiguration
> `Access-Control-Allow-Origin: *` — any website can call your API.
> Response headers reveal: `X-Powered-By: Express 4.17.1` and `Server: Ubuntu 20.04 / Node 14.x`

### API9: Improper Inventory Management
> Undocumented endpoint `/api/v2-beta/debug/config` returns all env vars including database passwords.
> Not in the OpenAPI spec → never reviewed by security team.

### API10: Unsafe Consumption of External APIs
> Webhook endpoint trusts all incoming data without verifying the HMAC signature.
> Attacker sends `{"event": "payment_success"}` → gets free goods without paying.

## How to Test These

```bash
# Start the API
node api/rest_api_insecure.js

# Test API1 — BOLA: read user 1's data while logged in as user 2
curl http://localhost:3001/api/v1/users/1

# Test API7 — SSRF: make server fetch internal metadata
curl "http://localhost:3001/api/v1/proxy?url=http://169.254.169.254/latest/meta-data/"

# Test API9 — Shadow endpoint
curl http://localhost:3001/api/v2-beta/debug/config
```

## Learn More
- [GLOSSARY.md](../GLOSSARY.md) → look up: BOLA, IDOR, SSRF, XSS
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
