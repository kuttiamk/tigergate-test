// =============================================================================
// sast_advanced/deserialization_gadget.js – TigerGate CNAPP: Advanced SAST
// =============================================================================
// PURPOSE: Demonstrates a multi-stage CWE-502 deserialization exploit via
// `node-serialize` — an actual historical CVE (CVE-2017-5941).
//
// SAST FINDINGS:
//   CWE-502: Deserialization of Untrusted Data → Remote Code Execution
//   CWE-20:  Improper Input Validation
//   CWE-78:  OS Command Injection via IIFE in serialized payload
//   SonarQube Rule: S5042 — Expanding Archives is Security-Sensitive
// =============================================================================

const serialize = require('node-serialize');   // BAD: node-serialize has known RCE CVE
const express = require('express');
const app = express();

// BAD: Secret hardcoded at module scope
const SECRET = "node_super_secret_1234";

// =============================================================================
// 🔴 VULN: CWE-502 - Insecure Deserialization -> RCE via IIFE gadget
// The payload below is a real exploit proof-of-concept.
// When 'unserialize()' processes an object with a function prefixed by (),
// node-serialize will EXECUTE the function immediately (IIFE = Immediately
// Invoked Function Expression).
//
// EXPLOIT PAYLOAD (for educational reference):
//   {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
//
// REAL CVE: CVE-2017-5941 (node-serialize < 0.0.5)
// =============================================================================
app.post('/api/profile', express.text({ type: '*/*' }), (req, res) => {
    try {
        // BAD: Direct deserialization of user-controlled POST body
        const userProfile = serialize.unserialize(req.body);  // 🔴 RCE via IIFE gadget!
        res.json({ success: true, user: userProfile });
    } catch (err) {
        // BAD: Stack trace exposed to client
        res.status(500).json({ error: err.stack });           // 🔴 Information Disclosure
    }
});

// =============================================================================
// 🔴 VULN: JavaScript Prototype Pollution (CWE-1321)
// A merge operation that does not block __proto__ manipulation.
// Attacker sets: {"__proto__":{"isAdmin":true}} → all objects get isAdmin:true
// =============================================================================
function mergeObjects(target, source) {
    for (const key of Object.keys(source)) {
        // BAD: No check for `key === '__proto__'` or `key === 'constructor'`
        if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = mergeObjects(target[key] || {}, source[key]);   // 🔴 Prototype Pollution
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

app.post('/api/settings', express.json(), (req, res) => {
    const defaultSettings = { theme: 'light', language: 'en' };
    // BAD: Merges user-controlled JSON into app settings object without sanitization
    const userSettings = mergeObjects(defaultSettings, req.body);         // 🔴 Prototype Pollution!
    res.json({ settings: userSettings });
});

// =============================================================================
// 🔴 VULN: CWE-915 - Mass Assignment / Insufficient Property Restriction
// An ORM-like update that blindly assigns all user-controlled fields to model
// =============================================================================
app.put('/api/users/:id', express.json(), (req, res) => {
    const userId = req.params.id;
    const updateFields = req.body;                    // BAD: All fields from user input!

    // BAD: Allows user to update ANY field, including privileged ones like 'role': 'admin'
    // or 'isVerified': true, or 'creditBalance': 99999
    const updateQuery = `UPDATE users SET ${Object.entries(updateFields).map(([k, v]) => `${k}='${v}'`).join(', ')   // 🔴 SQL Injection too!
        } WHERE id = ${userId}`;                          // 🔴 SQL Injection on userId!

    // BAD: Query is built but never executed (simulated), just returned as proof
    res.json({ query: updateQuery });                 // 🔴 Information Disclosure!
});

app.listen(4000, () => {
    console.log(`SAST Advanced Server running on :4000`);
    console.log(`SECRET: ${SECRET}`);                // 🔴 BAD: Secret logged to stdout!
});
