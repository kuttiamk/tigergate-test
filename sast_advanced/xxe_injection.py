# =============================================================================
# sast_advanced/xxe_injection.py — TigerGate CNAPP: SAST – XML/SSRF/Path Traversal
# =============================================================================
# PURPOSE: Demonstrates advanced injection vulnerabilities beyond SQL injection.
# Covers XXE (XML External Entity), SSRF, and path traversal — all in the
# OWASP Top 10 (A03:2021 Injection, A10:2021 SSRF).
#
# SAST FINDINGS:
#   SAST-XXE-001: XML parsed with external entity processing enabled (CWE-611)
#   SAST-XXE-002: LXML etree without defenses — DTD not disabled
#   SAST-SSRF-001: User URL fetched server-side without allowlist (CWE-918)
#   SAST-PATH-001: Path traversal via os.path.join with user data (CWE-22)
#   SAST-PATH-002: Open redirect using user-controlled URL
# =============================================================================

from flask import Flask, request, jsonify, redirect
import xml.etree.ElementTree as ET
import lxml.etree as lxml_ET
import os, requests, urllib.request

app = Flask(__name__)

BASE_UPLOAD_DIR = "/var/www/uploads"

# ── SAST-XXE-001: Standard library XXE ───────────────────────────────────────
@app.route('/api/parse-xml', methods=['POST'])
def parse_xml():
    """
    🔴 SAST-XXE-001: xml.etree.ElementTree does NOT protect against XXE but
    lxml does unless resolve_entities is explicitly enabled.

    XXE Attack payload:
    <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <user><name>&xxe;</name></user>

    Result: Server reads /etc/passwd and returns it in the response!
    """
    xml_data = request.data
    # 🔴 SAST-XXE-001: Parsing untrusted XML without disabling external entities
    root = ET.fromstring(xml_data)   # Vulnerable to Billion Laughs DoS
    return jsonify({"parsed": root.tag, "text": root.text})

# ── SAST-XXE-002: lxml with external entities enabled ────────────────────────
@app.route('/api/parse-xml-lxml', methods=['POST'])
def parse_xml_lxml():
    """🔴 SAST-XXE-002: lxml with resolve_entities=True (explicitly unsafe)."""
    xml_data = request.data
    # 🔴 SAST-XXE-002: resolve_entities=True allows reading /etc/passwd, /etc/shadow, etc.
    parser = lxml_ET.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
    root = lxml_ET.fromstring(xml_data, parser=parser)
    return jsonify({"tag": root.tag})
    # Fix:
    # parser = lxml_ET.XMLParser(resolve_entities=False, no_network=True)

# ── SAST-SSRF-001: Server-Side Request Forgery ───────────────────────────────
@app.route('/api/fetch-url')
def fetch_url():
    """
    🔴 SAST-SSRF-001: User-provided URL fetched server-side without validation.

    SSRF attacks via this endpoint:
    1. http://169.254.169.254/latest/meta-data/  → AWS credentials
    2. http://localhost:6379/keys/*             → Redis data dump
    3. http://internal-db:5432/                → Internal service probe
    4. file:///etc/passwd                      → Local file read
    5. http://attacker.com/ssrf-log            → SSRF-to-RCE chaining
    """
    url = request.args.get('url')   # 🔴 SAST-SSRF-001: User controls the URL!
    if not url:
        return jsonify({"error": "url param required"})

    # 🔴 SAST-SSRF-001: No allowlist check — any internal or sensitive URL works
    try:
        response = requests.get(url, timeout=5)   # 🔴 Server fetches attacker-controlled URL
        return jsonify({"content": response.text[:500], "status": response.status_code})
    except Exception as e:
        return jsonify({"error": str(e)})
    # Fix: validate against allowlist of approved domains before fetching

# ── SAST-PATH-001: Path Traversal ────────────────────────────────────────────
@app.route('/api/download')
def download_file():
    """
    🔴 SAST-PATH-001: Path traversal via user-supplied filename.
    Attack: /api/download?file=../../etc/passwd
    Attack: /api/download?file=../../../proc/self/environ  (env vars with secrets!)
    """
    filename = request.args.get('file', '')
    # 🔴 SAST-PATH-001: os.path.join with user input — attacker can escape BASE_UPLOAD_DIR!
    file_path = os.path.join(BASE_UPLOAD_DIR, filename)   # "../../etc/passwd" escapes!
    # 🔴 No check that file_path starts with BASE_UPLOAD_DIR after resolution
    with open(file_path, 'r') as f:   # Reads any file the server process can access
        return f.read()
    # Fix:
    # safe_path = os.path.realpath(file_path)
    # if not safe_path.startswith(os.path.realpath(BASE_UPLOAD_DIR)):
    #     return "Access denied", 403

# ── SAST-PATH-002: Open Redirect ─────────────────────────────────────────────
@app.route('/api/login-redirect')
def login_redirect():
    """
    🔴 SAST-PATH-002: Open redirect — used in phishing to send victims to evil site.
    Attack: /api/login-redirect?next=https://evil.com/phishing-page
    Google, Microsoft, PayPal ban open redirects via their bug bounty programs.
    """
    next_url = request.args.get('next', '/')
    # 🔴 SAST-PATH-002: User controls redirect destination — phishing amplifier!
    return redirect(next_url)   # Should validate next_url is a relative path on same domain

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
