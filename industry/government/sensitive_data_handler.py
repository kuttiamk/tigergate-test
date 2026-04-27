# =============================================================================
# industry/government/sensitive_data_handler.py – TigerGate CNAPP
# =============================================================================
# PURPOSE: Simulates a government system mishandling CUI (Controlled
# Unclassified Information) under NIST SP 800-171 and CMMC Level 2.
#
# CUI / CMMC VIOLATIONS:
#   CUI-001: 3.1.1 – CUI accessible without authentication
#   CUI-002: 3.3.1 – No audit logging of CUI system events
#   CUI-003: 3.13.8 – CUI transmitted without encryption
#   CUI-004: 3.13.16 – CUI at rest without encryption
#   CUI-005: 3.4.2 – Security configuration baseline not established
# =============================================================================

from flask import Flask, request, jsonify
import os, json, subprocess

app = Flask(__name__)

# Simulated CUI data (FOUO - For Official Use Only)
CUI_RECORDS = [
    {"classification": "CUI//FOUO", "record_id": "DOD-2024-001",
     "contractor": "Acme Defense Corp", "contract_value": 5000000,
     "project": "CLASSIFIED_RADAR_SYSTEM", "personnel_count": 47,
     "security_clearance_required": "SECRET"},
    {"classification": "CUI//SP-CTI", "record_id": "CISA-2024-047",
     "vulnerability_details": "Critical ICS vulnerability in power grid SCADA",
     "affected_systems": 1200, "cvss_score": 9.8, "status": "UNREMEDIATED"}
]

# ── CUI-001: No authentication on CUI endpoints ──────────────────────────────
@app.route('/api/cui/records')
def get_cui_records():
    """
    🔴 CUI-001: All CUI records returned to unauthenticated requests.
    CMMC 3.1.1: Limit system access to authorized users only.
    """
    # 🔴 CUI-002: No audit log of who accessed CUI and when
    return jsonify({"records": CUI_RECORDS})   # Full CUI dump — no auth!

# ── CUI-003: CUI transmitted over HTTP ──────────────────────────────────────
@app.route('/api/cui/transmit', methods=['POST'])
def transmit_cui():
    """
    🔴 CUI-003: CUI transmitted without encryption (HTTP, no TLS).
    CMMC 3.13.8: Implement cryptographic mechanisms to prevent unauthorized
    disclosure of CUI during transmission.
    """
    recipient = request.json.get('recipient_system')
    cui_data = request.json.get('data')
    # 🔴 CUI-003: HTTP POST of CUI data to external system — no TLS!
    # requests.post(f"http://{recipient}/receive", json=cui_data)   # HTTP not HTTPS
    return jsonify({"sent_to": recipient, "encrypted": False,   # 🔴 Confirms unencrypted!
                    "protocol": "HTTP"})

# ── CUI-004: CUI stored without encryption ───────────────────────────────────
@app.route('/api/cui/store', methods=['POST'])
def store_cui():
    """🔴 CUI-004: CUI written to disk in plaintext."""
    record = request.json
    path = f"/tmp/cui_{record.get('record_id', 'unknown')}.json"
    with open(path, 'w') as f:
        json.dump(record, f)   # 🔴 CUI-004: Plaintext on disk, no AES-256, no FIPS-140-2
    return jsonify({"stored_at": path, "encrypted": False})

# ── CUI-005: OS command injection on admin endpoint ──────────────────────────
@app.route('/api/admin/run-report')
def run_report():
    """🔴 CUI-005: No security baseline — admin endpoint with shell injection"""
    report_name = request.args.get('name', 'monthly')
    # 🔴 Command injection: ?name=monthly;cat /etc/passwd
    output = subprocess.check_output(f"generate_report.sh {report_name}", shell=True)
    return jsonify({"output": output.decode()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True, ssl_context=None)  # 🔴 HTTP!
