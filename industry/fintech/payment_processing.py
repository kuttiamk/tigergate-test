# =============================================================================
# industry/fintech/payment_processing.py – TigerGate CNAPP: FinTech Industry
# =============================================================================
# PURPOSE: Simulates FinTech / payment application vulnerabilities.
# Triggers DSPM PCI-DSS findings, SAST PII handling issues, and CIEM findings.
#
# PCI-DSS v4.0 VIOLATIONS TRIGGERED:
#   PCI-001: Req 3.4 – Full PAN stored in plaintext database (no masking)
#   PCI-002: Req 3.5 – CVV stored after authorization (must not store)
#   PCI-003: Req 4.2 – PAN transmitted without encryption (HTTP endpoint)
#   PCI-004: Req 6.4 – Application processes sensitive data via eval()
#   PCI-005: Req 8.3 – No MFA for administrative access
#   PCI-006: Req 10.3 – Audit log missing payment transaction events
#   PCI-007: Req 12.3.1 – No token-based cardholder data isolation
# =============================================================================

from flask import Flask, request, jsonify
import sqlite3, hashlib, logging, os, json

app = Flask(__name__)
app.config['DEBUG'] = True  # 🔴 PCI-004: Debug mode in production

# 🔴 PCI-001 / PCI-002: Database stores full PAN + CVV in plaintext
DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY,
    card_number TEXT,       -- 🔴 PCI-001: Full 16-digit PAN stored unmasked
    cvv TEXT,               -- 🔴 PCI-002: CVV MUST NOT be stored! PCI req 3.2
    cardholder_name TEXT,
    expiry TEXT,
    amount REAL,
    merchant_id TEXT,
    status TEXT
)
"""

# Weak single-iteration MD5 — not PBKDF2/bcrypt/Argon2 (PCI Req 8.3.6)
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()  # 🔴 BAD: MD5 is not PCI-approved

# 🔴 PCI-003: Payment endpoint over HTTP with no TLS enforcement
@app.route('/api/payment', methods=['POST'])
def process_payment():
    data = request.json

    # 🔴 PCI-001: Stores full card number without masking
    card_number = data.get('card_number')    # Full PAN 4111111111111111
    cvv = data.get('cvv')                    # 🔴 PCI-002: CVV cannot be stored
    cardholder = data.get('name')
    amount = data.get('amount')

    # 🔴 PCI-006: No audit logging of payment attempt
    # logging.info(f"Payment attempt for {cardholder}") — NOT called

    conn = sqlite3.connect('/tmp/payments.db')
    cursor = conn.cursor()
    cursor.execute(DB_SCHEMA)

    # 🔴 PCI-001: Storing full PAN and CVV in plaintext column
    cursor.execute(
        "INSERT INTO transactions (card_number, cvv, cardholder_name, amount, status) VALUES (?, ?, ?, ?, ?)",
        (card_number, cvv, cardholder, amount, 'pending')
    )
    conn.commit()

    # 🔴 PCI-007: Response returns full PAN back to client (should be masked)
    return jsonify({
        'status': 'success',
        'card': card_number,   # 🔴 BAD: Returns full PAN in response!
        'transaction_id': cursor.lastrowid
    })

# 🔴 PCI-005: Admin endpoint with no MFA or role verification
@app.route('/api/admin/transactions')
def admin_view():
    # 🔴 BAD: No authentication, no MFA, anyone can call this
    conn = sqlite3.connect('/tmp/payments.db')
    cursor = conn.cursor()
    # 🔴 BAD: Returns ALL transactions with full PAN/CVV data
    cursor.execute("SELECT * FROM transactions")
    rows = cursor.fetchall()
    return jsonify({'transactions': rows})   # 🔴 Mass PCI data dump!

# 🔴 PCI-004: Processing financial formula via eval() (code injection)
@app.route('/api/calculate-fee')
def calculate_fee():
    formula = request.args.get('formula', '0')
    # 🔴 BAD: eval() executes attacker-controlled math expression
    # Payload: ?formula=__import__('os').system('id')
    result = eval(formula)    # 🔴 VULN: RCE via formula injection!
    return jsonify({'fee': result})

# 🔴 DSPM: Export all customer financial data to S3 bucket (without encryption)
@app.route('/api/export-data')
def export_financial_data():
    # 🔴 BAD: Exports PAN/CVV data to an unencrypted public S3 bucket
    bucket_url = "https://megacorp-financial-data.s3.amazonaws.com/export/"
    conn = sqlite3.connect('/tmp/payments.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transactions")
    data = cursor.fetchall()
    return jsonify({'export_url': bucket_url, 'records': len(data)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7000, debug=True)   # 🔴 PCI: No TLS on payment server!
